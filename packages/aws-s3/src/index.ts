import { createHash } from 'node:crypto';
import { DeleteObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
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
}

export { S3CompatiblePackageStore as S3ProtectedPackageStore };
