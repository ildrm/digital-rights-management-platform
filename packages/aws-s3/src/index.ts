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

  constructor(
    client: S3Client,
    bucket: string,
    sseKmsKeyArn?: string,
  ) {
    if (!BUCKET.test(bucket) || bucket.includes('..') || bucket.includes('.-') || bucket.includes('-.') ||
        (sseKmsKeyArn !== undefined && !KMS_ARN.test(sseKmsKeyArn))) {
      throw new DomainError('INVALID_STORAGE_CONFIG', 'A private S3-compatible bucket name and optional concrete KMS key ARN are required');
    }
    this.client = client;
    this.bucket = bucket;
    this.sseKmsKeyArn = sseKmsKeyArn;
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
    await this.client.send(new PutObjectCommand({
      Bucket: this.bucket, Key: key, Body: body,
      ContentType: 'application/vnd.drm.secure-package+json',
      ContentLength: body.length,
      ChecksumSHA256: digest.toString('base64'),
      ...(this.sseKmsKeyArn ? { ServerSideEncryption: 'aws:kms' as const, SSEKMSKeyId: this.sseKmsKeyArn } : {}),
      IfNoneMatch: '*',
      Metadata: { 'package-sha256': digest.toString('hex') },
    }));
    return { sha256: digest.toString('hex'), bytes: body.length };
  }

  async delete(key: string): Promise<void> {
    if (!OBJECT_KEY.test(key)) throw new DomainError('INVALID_STORAGE_KEY', 'Package object key is invalid');
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }

  async get(key: string, expectedSha256: string, expectedBytes: number): Promise<Buffer> {
    if (!OBJECT_KEY.test(key) || !/^[a-f0-9]{64}$/.test(expectedSha256) ||
        !Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > 100 * 1024 * 1024) {
      throw new DomainError('INVALID_STORAGE_KEY', 'Package retrieval metadata is invalid');
    }
    let output;
    try {
      output = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }),
        { abortSignal: AbortSignal.timeout(10_000) });
    } catch {
      throw new DomainError('STORAGE_UNAVAILABLE', 'Package storage is unavailable');
    }
    if (output.ContentLength !== undefined && output.ContentLength !== expectedBytes) {
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package length differs from catalog');
    }
    if (!output.Body || !(Symbol.asyncIterator in output.Body)) {
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package body is unavailable');
    }
    const chunks: Buffer[] = [];
    const digest = createHash('sha256');
    let total = 0;
    try {
      for await (const chunk of output.Body as AsyncIterable<Uint8Array>) {
        if (!(chunk instanceof Uint8Array)) throw new Error('Invalid package chunk');
        total += chunk.length;
        if (total > expectedBytes) throw new Error('Package exceeds catalog length');
        const bytes = Buffer.from(chunk);
        digest.update(bytes);
        chunks.push(bytes);
      }
    } catch {
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package body could not be read safely');
    }
    if (total !== expectedBytes || digest.digest('hex') !== expectedSha256) {
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package checksum differs from catalog');
    }
    return Buffer.concat(chunks, total);
  }
}

export { S3CompatiblePackageStore as S3ProtectedPackageStore };
