import type { Pool } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface PackageReadRequest {
  readonly tenantId: string;
  readonly authenticatedUserId: string;
  readonly assetId: string;
  readonly renditionId: string;
  readonly licenseId: string;
}

export interface ReadablePackageStore {
  get(key: string, expectedSha256: string, expectedBytes: number): Promise<Buffer>;
}

interface PackageRow {
  object_key: string;
  package_sha256: Buffer;
  package_bytes: number;
}

export class PostgresPackageReader {
  private readonly pool: Pool;
  private readonly store: ReadablePackageStore;

  constructor(pool: Pool, store: ReadablePackageStore) {
    this.pool = pool;
    this.store = store;
  }

  async read(value: PackageReadRequest): Promise<Buffer> {
    const fields = ['tenantId', 'authenticatedUserId', 'assetId', 'renditionId', 'licenseId'] as const;
    if (!value || typeof value !== 'object' || Object.keys(value).length !== fields.length ||
      fields.some((field) => typeof value[field] !== 'string' || !UUID.test(value[field]))) {
      throw new DomainError('INVALID_REQUEST', 'Package request identifiers must be UUIDs');
    }
    const request = Object.fromEntries(fields.map((field) => [field, value[field].toLowerCase()])) as unknown as PackageReadRequest;
    const row = await withTenantTransaction(this.pool, request.tenantId, async (client) => {
      const result = await client.query<PackageRow>(
        `SELECT ap.object_key, ap.package_sha256, ap.package_bytes
         FROM drm.asset_packages ap
         JOIN drm.assets a ON a.tenant_id = ap.tenant_id AND a.id = ap.asset_id
         JOIN drm.entitlements e ON e.tenant_id = ap.tenant_id
           AND e.asset_id = ap.asset_id AND e.asset_version = ap.asset_version
         JOIN drm.licenses l ON l.tenant_id = e.tenant_id AND l.entitlement_id = e.id
           AND l.rendition_id = ap.rendition_id
         JOIN drm.devices d ON d.tenant_id = l.tenant_id AND d.id = l.device_id
         JOIN drm.users u ON u.tenant_id = e.tenant_id AND u.id = e.subject_user_id
         JOIN drm.rendition_keys rk ON rk.tenant_id = ap.tenant_id
           AND rk.asset_id = ap.asset_id AND rk.asset_version = ap.asset_version
           AND rk.rendition_id = ap.rendition_id
         WHERE ap.tenant_id = $1 AND ap.asset_id = $2 AND ap.rendition_id = $3
           AND l.id = $4 AND e.subject_user_id = $5 AND d.user_id = $5
           AND u.status = 'active' AND a.status = 'published'
           AND e.status = 'active' AND e.valid_from <= clock_timestamp()
           AND (e.valid_until IS NULL OR e.valid_until > clock_timestamp())
           AND l.revoked_at IS NULL AND l.issued_at <= clock_timestamp()
           AND l.expires_at > clock_timestamp() AND d.revoked_at IS NULL
           AND rk.status = 'active'`,
        [request.tenantId, request.assetId, request.renditionId,
          request.licenseId, request.authenticatedUserId],
      );
      return result.rows[0];
    });
    if (!row || !Buffer.isBuffer(row.package_sha256) || row.package_sha256.length !== 32 ||
        !Number.isSafeInteger(row.package_bytes) || row.package_bytes < 1 ||
        row.package_bytes > 100 * 1024 * 1024) {
      throw new DomainError('ACCESS_DENIED', 'Licensed package is unavailable');
    }
    return this.store.get(row.object_key, row.package_sha256.toString('hex'), row.package_bytes);
  }
}
