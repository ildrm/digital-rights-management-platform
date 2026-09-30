import { createHash, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { canonicalJson, compilePolicy, createSecurePackage, DomainError, type KeyWrapper, type LicenseSigner, type Policy, type SecurePackage } from '@drm/core';
import { appendOutboxEvent } from './outbox.ts';
import { TransactionCommitUnknownError, withTenantTransaction } from './tenant-transaction.ts';

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
  get(key: string, expectedSha256: string, expectedBytes: number): Promise<Buffer>;
}

export interface PublishAssetInput {
  readonly idempotencyKey: string;
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

interface PublicationDraft {
  readonly asset: PublishedAsset;
  readonly policy: Policy;
  readonly policyDigest: string;
  readonly contentSha256: string;
  readonly packageBytes: number;
  readonly mimeType: string;
  readonly keyReference: string;
  readonly signingKeyId: string;
}

interface OperationRow {
  id: string;
  owner_user_id: string;
  request_sha256: Buffer;
  status: 'pending' | 'committed' | 'abandoned';
  document: PublicationDraft;
  encrypted_package: SecurePackage | null;
}

export class PostgresAssetPublisher {
  private readonly pool: Pool;
  private readonly store: ProtectedPackageStore;
  private readonly keys: KeyWrapper;
  private readonly signer: LicenseSigner;
  constructor(
    pool: Pool, store: ProtectedPackageStore, keys: KeyWrapper, signer: LicenseSigner,
  ) {
    this.pool = pool;
    this.store = store;
    this.keys = keys;
    this.signer = signer;
  }

  async publish(value: PublishAssetInput): Promise<PublishedAsset> {
    if (!value || ![value.tenantId, value.ownerUserId, value.idempotencyKey].every((id) => typeof id === 'string' && UUID.test(id))) {
      throw new DomainError('INVALID_REQUEST', 'Tenant, owner and idempotency key must be UUIDs');
    }
    if (!Buffer.isBuffer(value.content) || value.content.length < 1 || value.content.length > MAX_CONTENT_BYTES) {
      throw new DomainError('INVALID_CONTENT', 'Content must be 1–67108864 bytes');
    }
    if (typeof value.mimeType !== 'string' || value.mimeType.length > 256 || !MIME.test(value.mimeType)) {
      throw new DomainError('INVALID_MIME', 'A concrete MIME type is required');
    }
    if (!value.policy || typeof value.policy !== 'object' || Array.isArray(value.policy)) throw new DomainError('INVALID_POLICY', 'Policy required');
    const input = { ...value, tenantId: value.tenantId.toLowerCase(), ownerUserId: value.ownerUserId.toLowerCase(),
      idempotencyKey: value.idempotencyKey.toLowerCase(), content: Buffer.from(value.content), policy: structuredClone(value.policy) };
    try {
      const requestDigest = createHash('sha256').update('publication-request-v1\0')
        .update(canonicalJson({ owner: input.ownerUserId, mimeType: input.mimeType, policy: input.policy,
          contentSha256: createHash('sha256').update(input.content).digest('hex') })).digest();
      const existing = await this.operation(input.tenantId, input.ownerUserId, input.idempotencyKey);
      if (existing) {
        this.match(existing, requestDigest);
        return await this.resume(input.tenantId, input.idempotencyKey, input.ownerUserId);
      }
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
        policy.constraints.assetVersion !== undefined && policy.constraints.assetVersion !== '1' ||
        policy.constraints.minimumDeviceTrust === 'hardware' || policy.constraints.onlineOnly !== true) {
        throw new DomainError('UNSUPPORTED_POLICY', 'Publishing requires an online-only policy supported by the current license issuer');
      }
      const pkg = await createSecurePackage(input.content, {
        tenantId: input.tenantId, assetId, assetVersion: '1', renditionId, mimeType: input.mimeType,
      }, this.keys, this.signer);
      // JSON is the storage wire format. Persist the exact encrypted package before attempting upload.
      const bytes = Buffer.from(JSON.stringify(pkg));
      const asset: PublishedAsset = { assetId, policyId, renditionId, version: 1,
        objectKey: `tenants/${input.tenantId}/assets/${assetId}/versions/1/renditions/${renditionId}.drmpkg`,
        packageSha256: createHash('sha256').update(bytes).digest('hex') };
      const draft: PublicationDraft = { asset, policy, policyDigest: compiled.sourceDigest,
        contentSha256: createHash('sha256').update(input.content).digest('hex'), packageBytes: bytes.length,
        mimeType: input.mimeType, keyReference: pkg.manifest.wrappedKey.keyReference, signingKeyId: pkg.manifest.signingKeyId };
      await withTenantTransaction(this.pool, input.tenantId, async (client) => {
        await client.query('SELECT 1 FROM drm.users WHERE tenant_id = $1 AND id = $2 FOR UPDATE', [input.tenantId, input.ownerUserId]);
        await this.activeOwner(client, input.tenantId, input.ownerUserId);
        const outstanding = await client.query<{ count: number; bytes: string }>(`SELECT count(*)::integer AS count,
          COALESCE(sum((document->>'packageBytes')::bigint), 0)::text AS bytes FROM drm.publication_operations
          WHERE tenant_id = $1 AND owner_user_id = $2 AND status = 'pending' AND id <> $3`,
        [input.tenantId, input.ownerUserId, input.idempotencyKey]);
        if ((outstanding.rows[0]?.count ?? 0) >= 8 || Number(outstanding.rows[0]?.bytes ?? 0) + bytes.length > 128 * 1024 * 1024) {
          throw new DomainError('PUBLICATION_CAPACITY', 'Pending publication capacity reached; retry existing operations first');
        }
        await client.query(`INSERT INTO drm.publication_operations
          (tenant_id, id, owner_user_id, request_sha256, document, encrypted_package)
          VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, id) DO NOTHING`,
        [input.tenantId, input.idempotencyKey, input.ownerUserId, requestDigest, draft, pkg]);
        const row = await client.query<OperationRow>(
          'SELECT * FROM drm.publication_operations WHERE tenant_id = $1 AND id = $2', [input.tenantId, input.idempotencyKey]);
        this.match(row.rows[0]!, requestDigest);
      });
      return await this.resume(input.tenantId, input.idempotencyKey, input.ownerUserId);
    } catch (error) {
      if (error instanceof TransactionCommitUnknownError) throw new DomainError('PUBLISH_UNCERTAIN', 'Retry using the same idempotency key');
      throw error;
    } finally {
      input.content.fill(0);
    }
  }

  private match(row: Pick<OperationRow, 'request_sha256'>, digest: Buffer): void {
    if (!row.request_sha256.equals(digest)) throw new DomainError('IDEMPOTENCY_CONFLICT', 'Idempotency key was already used for different publication content');
  }

  private async operation(tenantId: string, ownerId: string, id: string): Promise<Omit<OperationRow, 'encrypted_package'> | undefined> {
    return withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query<Omit<OperationRow, 'encrypted_package'>>(
        'SELECT id, owner_user_id, request_sha256, status, document FROM drm.publication_operations WHERE tenant_id = $1 AND owner_user_id = $2 AND id = $3', [tenantId, ownerId, id]);
      return result.rows[0];
    });
  }

  async status(tenantId: string, ownerId: string, id: string): Promise<{ status: OperationRow['status']; asset?: PublishedAsset }> {
    if (![tenantId, ownerId, id].every((value) => typeof value === 'string' && UUID.test(value))) throw new DomainError('INVALID_REQUEST', 'UUIDs required');
    const operation = await this.operation(tenantId, ownerId, id);
    if (!operation) throw new DomainError('PUBLICATION_NOT_FOUND', 'Publication operation not found');
    return { status: operation.status, ...(operation.status === 'committed' ? { asset: operation.document.asset } : {}) };
  }

  private async resume(tenantId: string, id: string, ownerId?: string): Promise<PublishedAsset> {
    return withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query<OperationRow>(
        'SELECT * FROM drm.publication_operations WHERE tenant_id = $1 AND id = $2 FOR UPDATE', [tenantId, id]);
      const row = result.rows[0];
      if (!row || ownerId !== undefined && row.owner_user_id !== ownerId) throw new DomainError('PUBLICATION_NOT_FOUND', 'Publication operation not found');
      if (row.status === 'committed') return row.document.asset;
      if (row.status === 'abandoned') throw new DomainError('PUBLICATION_ABANDONED', 'Publication expired; submit a new idempotency key');
      const d = row.document;
      const a = d.asset;
      try {
        const receipt = await this.store.put(a.objectKey, row.encrypted_package!);
        if (receipt.sha256 !== a.packageSha256 || receipt.bytes !== d.packageBytes) throw new Error('Storage receipt mismatch');
      } catch {
        // Conditional-put conflict or lost upload acknowledgement: verify the existing bytes.
        // An unavailable read never authorizes deletion or catalog publication.
        try { await this.store.get(a.objectKey, a.packageSha256, d.packageBytes); }
        catch { throw new DomainError('PUBLISH_UNCERTAIN', 'Retry using the same idempotency key'); }
      }
      await this.activeOwner(client, tenantId, row.owner_user_id);
      await this.commitDraft(client, tenantId, row.owner_user_id, d);
      await client.query(`UPDATE drm.publication_operations SET status = 'committed', encrypted_package = NULL,
        updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2`, [tenantId, id]);
      return a;
    });
  }

  private async activeOwner(client: PoolClient, tenantId: string, ownerId: string): Promise<void> {
    const owner = await client.query("SELECT 1 FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR SHARE", [tenantId, ownerId]);
    if (owner.rowCount !== 1) throw new DomainError('ACCESS_DENIED', 'Active owner required');
  }

  private async commitDraft(client: PoolClient, tenantId: string, ownerId: string, d: PublicationDraft): Promise<void> {
    const a = d.asset;
    await client.query("INSERT INTO drm.assets (tenant_id, id, owner_user_id, status) VALUES ($1, $2, $3, 'published')", [tenantId, a.assetId, ownerId]);
    await client.query('INSERT INTO drm.asset_versions (tenant_id, asset_id, version, sha256) VALUES ($1, $2, 1, $3)', [tenantId, a.assetId, Buffer.from(d.contentSha256, 'hex')]);
    await client.query('INSERT INTO drm.policies (tenant_id, id, version, asset_id, document, digest) VALUES ($1, $2, 1, $3, $4, $5)', [tenantId, a.policyId, a.assetId, d.policy, Buffer.from(d.policyDigest, 'hex')]);
    await client.query(`INSERT INTO drm.rendition_keys (tenant_id, asset_id, asset_version, rendition_id, target, key_reference, status)
      VALUES ($1, $2, 1, $3, 'secureViewer', $4, 'active')`, [tenantId, a.assetId, a.renditionId, d.keyReference]);
    await client.query(`INSERT INTO drm.asset_packages
      (tenant_id, asset_id, asset_version, rendition_id, object_key, package_sha256, package_bytes, mime_type, manifest_signing_key_id)
      VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8)`, [tenantId, a.assetId, a.renditionId, a.objectKey, Buffer.from(a.packageSha256, 'hex'), d.packageBytes, d.mimeType, d.signingKeyId]);
    await client.query(`INSERT INTO drm.audit_events (tenant_id, id, actor_id, event_type, details)
      VALUES ($1, $2, $3, 'asset.published', $4)`, [tenantId, randomUUID(), ownerId, { ...a }]);
    await appendOutboxEvent(client, tenantId, 'asset.published', a.assetId, { assetId: a.assetId, version: 1, renditionId: a.renditionId, policyId: a.policyId });
  }

  /** Bounded recovery. Tombstones are retained and re-swept to catch delayed uploads. */
  async reconcile(tenantId: string, limit = 10): Promise<{ recovered: number; pending: number; cleaned: number }> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new DomainError('INVALID_REQUEST', 'Invalid reconciliation limit');
    const ids = await withTenantTransaction(this.pool, tenantId, async (client) => {
      await client.query(`UPDATE drm.publication_operations SET status = 'abandoned', encrypted_package = NULL,
        updated_at = clock_timestamp() WHERE tenant_id = $1 AND status = 'pending'
        AND id IN (SELECT id FROM drm.publication_operations WHERE tenant_id = $1 AND status = 'pending'
          AND created_at < clock_timestamp() - interval '24 hours' ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, [tenantId, limit]);
      const rows = await client.query<{ id: string }>(`SELECT id FROM drm.publication_operations WHERE tenant_id = $1
        AND status = 'pending' ORDER BY updated_at, id LIMIT $2`, [tenantId, limit]);
      return rows.rows;
    });
    let recovered = 0;
    let pending = 0;
    for (const { id } of ids) {
      try { await this.resume(tenantId, id); recovered++; }
      catch { pending++; }
      await withTenantTransaction(this.pool, tenantId, (client) => client.query(
        'UPDATE drm.publication_operations SET updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2', [tenantId, id]));
    }
    const abandoned = await withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query<OperationRow>(`SELECT * FROM drm.publication_operations WHERE tenant_id = $1
        AND status = 'abandoned' ORDER BY updated_at, id LIMIT $2`, [tenantId, limit]);
      return result.rows;
    });
    let cleaned = 0;
    for (const row of abandoned) {
      // Abandoned operations can never transition to committed; no catalog row can reference this key.
      await this.store.delete(row.document.asset.objectKey);
      await withTenantTransaction(this.pool, tenantId, (client) => client.query(
        'UPDATE drm.publication_operations SET updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2', [tenantId, row.id]));
      cleaned++;
    }
    return { recovered, pending, cleaned };
  }
}
