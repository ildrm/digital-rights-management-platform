import { createHash, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { compilePolicy, createSecurePackage, DomainError, type KeyWrapper, type LicenseSigner, type Policy, type SecurePackage } from '@drm/core';
import { appendOutboxEvent } from './outbox.ts';
import { withTenantTransaction } from './tenant-transaction.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_CONTENT_BYTES = 64 * 1024 * 1024;
const MIME = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;

export interface PackageReceipt {
  readonly sha256: string;
  readonly bytes: number;
}

export interface ProtectedPackageStore {
  put(key: string, pkg: SecurePackage): Promise<PackageReceipt>;
  delete(key: string): Promise<void>;
}

export interface PublishAssetInput {
  readonly tenantId: string;
  readonly ownerUserId: string;
  readonly content: Buffer;
  readonly mimeType: string;
  readonly policy: Omit<Policy, 'id' | 'version' | 'tenantId' | 'assetId'>;
}

export interface PublishedAsset {
  readonly assetId: string;
  readonly policyId: string;
  readonly renditionId: string;
  readonly version: 1;
  readonly objectKey: string;
  readonly packageSha256: string;
}

export class PostgresAssetPublisher {
  private readonly pool: Pool;
  private readonly store: ProtectedPackageStore;
  private readonly keys: KeyWrapper;
  private readonly signer: LicenseSigner;

  constructor(
    pool: Pool,
    store: ProtectedPackageStore,
    keys: KeyWrapper,
    signer: LicenseSigner,
  ) {
    this.pool = pool;
    this.store = store;
    this.keys = keys;
    this.signer = signer;
  }

  async publish(input: PublishAssetInput): Promise<PublishedAsset> {
    if (!UUID.test(input.tenantId) || !UUID.test(input.ownerUserId)) throw new DomainError('INVALID_REQUEST', 'Tenant and owner must be UUIDs');
    if (!Buffer.isBuffer(input.content) || input.content.length < 1 || input.content.length > MAX_CONTENT_BYTES) {
      throw new DomainError('INVALID_CONTENT', 'Content must be 1–67108864 bytes');
    }
    if (typeof input.mimeType !== 'string' || input.mimeType.length > 256 || !MIME.test(input.mimeType)) {
      throw new DomainError('INVALID_MIME', 'A concrete MIME type is required');
    }
    if (!input.policy || typeof input.policy !== 'object' || Array.isArray(input.policy)) throw new DomainError('INVALID_POLICY', 'Policy required');
    const content = Buffer.from(input.content);
    try {
      return await this.publishSnapshot({ ...input, content, policy: structuredClone(input.policy) });
    } finally {
      content.fill(0);
    }
  }

  private async publishSnapshot(input: PublishAssetInput): Promise<PublishedAsset> {
    const assetId = randomUUID();
    const policyId = randomUUID();
    const renditionId = randomUUID();
    const policy: Policy = { ...input.policy, id: policyId, version: 1, tenantId: input.tenantId, assetId };
    const compiled = compilePolicy(policy, 'secureViewer');
    if (!['controlled', 'protected'].includes(policy.profile) || !policy.preventOriginalPossession ||
      policy.permissions.length === 0 || policy.permissions.some((action) => !['view', 'read', 'play', 'listen'].includes(action)) ||
      policy.duties.length > 0 || policy.constraints.maxConcurrentSessions !== undefined ||
      policy.constraints.maxUses !== undefined || policy.constraints.maxExports !== undefined ||
      policy.constraints.territories !== undefined || policy.constraints.organizationId !== undefined ||
      policy.constraints.requiredRole !== undefined || policy.constraints.feature !== undefined ||
      policy.constraints.creditLimit !== undefined || policy.constraints.offlineSeconds !== undefined ||
      policy.constraints.minimumDeviceTrust === 'hardware' || policy.constraints.onlineOnly !== true) {
      throw new DomainError('UNSUPPORTED_POLICY', 'Publishing requires an online-only policy supported by the current license issuer');
    }
    await this.assertActiveOwner(input.tenantId, input.ownerUserId);
    const identity = {
      tenantId: input.tenantId, assetId, assetVersion: '1', renditionId, mimeType: input.mimeType,
    };
    const pkg = await createSecurePackage(input.content, identity, this.keys, this.signer);
    const objectKey = `tenants/${input.tenantId}/assets/${assetId}/versions/1/renditions/${renditionId}.drmpkg`;
    const receipt = await this.store.put(objectKey, pkg);
    if (!/^[a-f0-9]{64}$/.test(receipt.sha256) || !Number.isSafeInteger(receipt.bytes) || receipt.bytes < 1 || receipt.bytes > 100 * 1024 * 1024) {
      await this.store.delete(objectKey);
      throw new DomainError('INVALID_STORAGE_RECEIPT', 'Object store returned invalid package metadata');
    }
    try {
      await withTenantTransaction(this.pool, input.tenantId, async (client) => {
        const owner = await client.query(
          `SELECT 1 FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE`,
          [input.tenantId, input.ownerUserId],
        );
        if (owner.rowCount !== 1) throw new DomainError('ACCESS_DENIED', 'Active owner required');
        await client.query(
          `INSERT INTO drm.assets (tenant_id, id, owner_user_id, status) VALUES ($1, $2, $3, 'published')`,
          [input.tenantId, assetId, input.ownerUserId],
        );
        await client.query(
          `INSERT INTO drm.asset_versions (tenant_id, asset_id, version, sha256) VALUES ($1, $2, 1, $3)`,
          [input.tenantId, assetId, createHash('sha256').update(input.content).digest()],
        );
        await client.query(
          `INSERT INTO drm.policies (tenant_id, id, version, asset_id, document, digest) VALUES ($1, $2, 1, $3, $4, $5)`,
          [input.tenantId, policyId, assetId, policy, Buffer.from(compiled.sourceDigest, 'hex')],
        );
        await client.query(
          `INSERT INTO drm.rendition_keys (tenant_id, asset_id, asset_version, rendition_id, target, key_reference, status)
           VALUES ($1, $2, 1, $3, 'secureViewer', $4, 'active')`,
          [input.tenantId, assetId, renditionId, pkg.manifest.wrappedKey.keyReference],
        );
        await client.query(
          `INSERT INTO drm.asset_packages
           (tenant_id, asset_id, asset_version, rendition_id, object_key, package_sha256, package_bytes, mime_type, manifest_signing_key_id)
           VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8)`,
          [input.tenantId, assetId, renditionId, objectKey, Buffer.from(receipt.sha256, 'hex'), receipt.bytes, input.mimeType, pkg.manifest.signingKeyId],
        );
        await client.query(
          `INSERT INTO drm.audit_events (tenant_id, id, actor_id, event_type, details)
           VALUES ($1, $2, $3, 'asset.published', $4)`,
          [input.tenantId, randomUUID(), input.ownerUserId, { assetId, version: 1, renditionId, policyId, packageSha256: receipt.sha256 }],
        );
        await appendOutboxEvent(client, input.tenantId, 'asset.published', assetId,
          { assetId, version: 1, renditionId, policyId });
      });
    } catch (error) {
      try {
        await this.store.delete(objectKey);
      } catch (cleanupError) {
        throw new AggregateError([error, cleanupError], 'Publishing failed and encrypted object cleanup failed');
      }
      throw error;
    }
    return { assetId, policyId, renditionId, version: 1, objectKey, packageSha256: receipt.sha256 };
  }

  private async assertActiveOwner(tenantId: string, ownerUserId: string): Promise<void> {
    await withTenantTransaction(this.pool, tenantId, async (client) => {
      const owner = await client.query(
        `SELECT 1 FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active'`,
        [tenantId, ownerUserId],
      );
      if (owner.rowCount !== 1) throw new DomainError('ACCESS_DENIED', 'Active owner required');
    });
  }
}
