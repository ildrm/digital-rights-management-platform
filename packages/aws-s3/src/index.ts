import { createHash } from 'node:crypto';
import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { DomainError, type SecurePackage } from '@drm/core';
import type { PackageReceipt, ProtectedPackageStore } from '@drm/postgres';

const ID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const OBJECT_KEY = new RegExp(`^tenants\\/${ID}\\/assets\\/${ID}\\/versions\\/1\\/renditions\\/${ID}\\.drmpkg$`, 'i');
const KMS_ARN = /^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/i;
const BUCKET = /^(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

export class S3CompatiblePackageStore implements ProtectedPackageStore {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly sseKmsKeyArn: string | undefined;
  private readonly timeoutMs: number;

  constructor(
    client: S3Client,
    bucket: string,
    sseKmsKeyArn?: string,
    timeoutMs = 10_000,
  ) {
    if (!BUCKET.test(bucket) || bucket.includes('..') || bucket.includes('.-') || bucket.includes('-.') ||
        (sseKmsKeyArn !== undefined && !KMS_ARN.test(sseKmsKeyArn))) {
      throw new DomainError('INVALID_STORAGE_CONFIG', 'A private S3-compatible bucket name and optional concrete KMS key ARN are required');
    }
    this.client = client;
    this.bucket = bucket;
    this.sseKmsKeyArn = sseKmsKeyArn;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 60_000) throw new DomainError('INVALID_STORAGE_CONFIG', 'Invalid storage timeout');
    this.timeoutMs = timeoutMs;
  }

  async put(key: string, pkg: SecurePackage): Promise<PackageReceipt> {
    if (!OBJECT_KEY.test(key) || pkg.manifest.identity.tenantId !== key.split('/')[1] ||
        pkg.manifest.identity.assetId !== key.split('/')[3] ||
        pkg.manifest.identity.renditionId !== key.slice(key.lastIndexOf('/') + 1, -7) ||
        pkg.manifest.identity.assetVersion !== '1') {
      throw new DomainError('INVALID_STORAGE_KEY', 'Package identity and S3 key mismatch');
    }
    const body = Buffer.from(JSON.stringify(pkg));
    if (body.length < 1 || body.length > 100 * 1024 * 1024) throw new DomainError('INVALID_PACKAGE', 'Stored package too large');
    const digest = createHash('sha256').update(body).digest();
    try {
      await this.client.send(new PutObjectCommand({
        Bucket: this.bucket, Key: key, Body: body,
        ContentType: 'application/vnd.drm.secure-package+json',
        ContentLength: body.length,
        ChecksumSHA256: digest.toString('base64'),
        ...(this.sseKmsKeyArn ? { ServerSideEncryption: 'aws:kms' as const, SSEKMSKeyId: this.sseKmsKeyArn } : {}),
        IfNoneMatch: '*',
        Metadata: { 'package-sha256': digest.toString('hex') },
      }), { abortSignal: AbortSignal.timeout(this.timeoutMs) });
    } catch {
      throw new DomainError('STORAGE_UNAVAILABLE', 'Package storage write is unavailable');
    }
    return { sha256: digest.toString('hex'), bytes: body.length };
  }

  async delete(key: string): Promise<void> {
    if (!OBJECT_KEY.test(key)) throw new DomainError('INVALID_STORAGE_KEY', 'Package object key is invalid');
    try {
      await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
        { abortSignal: AbortSignal.timeout(this.timeoutMs) });
    } catch {
      throw new DomainError('STORAGE_UNAVAILABLE', 'Package storage deletion is unavailable');
    }
  }

  async get(key: string, expectedSha256: string, expectedBytes: number): Promise<Buffer> {
    if (!OBJECT_KEY.test(key) || !/^[a-f0-9]{64}$/.test(expectedSha256) ||
        !Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > 100 * 1024 * 1024) {
      throw new DomainError('INVALID_STORAGE_KEY', 'Package retrieval metadata is invalid');
    }
    const started = Date.now();
    let output;
    try {
      output = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }),
        { abortSignal: AbortSignal.timeout(this.timeoutMs) });
    } catch {
      throw new DomainError('STORAGE_UNAVAILABLE', 'Package storage is unavailable');
    }
    const body = output.Body;
    const closeBody = () => {
      if (body && 'destroy' in body && typeof body.destroy === 'function') body.destroy();
      else if (body && 'cancel' in body && typeof body.cancel === 'function') void body.cancel().catch(() => undefined);
    };
    if (output.ContentLength !== undefined && output.ContentLength !== expectedBytes) {
      closeBody();
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package length differs from catalog');
    }
    if (!body || !(Symbol.asyncIterator in body)) {
      closeBody();
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package body is unavailable');
    }
    const chunks: Buffer[] = [];
    const digest = createHash('sha256');
    let total = 0;
    let timedOut = false;
    const bodyTimer = setTimeout(() => { timedOut = true; closeBody(); }, Math.max(1, this.timeoutMs - (Date.now() - started)));
    try {
      for await (const chunk of body as AsyncIterable<Uint8Array>) {
        if (!(chunk instanceof Uint8Array)) throw new Error('Invalid package chunk');
        total += chunk.length;
        if (total > expectedBytes) throw new Error('Package exceeds catalog length');
        const bytes = Buffer.from(chunk);
        digest.update(bytes);
        chunks.push(bytes);
      }
    } catch {
      closeBody();
      if (timedOut) throw new DomainError('STORAGE_UNAVAILABLE', 'Package read timed out');
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package body could not be read safely');
    } finally {
      clearTimeout(bodyTimer);
    }
    if (timedOut) throw new DomainError('STORAGE_UNAVAILABLE', 'Package read timed out');
    if (total !== expectedBytes || digest.digest('hex') !== expectedSha256) {
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package checksum differs from catalog');
    }
    return Buffer.concat(chunks, total);
  }
}

export { S3CompatiblePackageStore as S3ProtectedPackageStore };
