import { createHash, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { DomainError, type SecurePackage } from '@drm/core';
import type { ProtectedPackageStore, PackageReceipt } from './publishing.ts';
import { withTenantTransaction } from './tenant-transaction.ts';

const ID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const OBJECT_KEY = new RegExp(`^tenants\/(${ID})\/assets\/(${ID})\/versions\/1\/renditions\/(${ID})\.drmpkg$`, 'i');
const MAX_PACKAGE_BYTES = 100 * 1024 * 1024;

function identity(key: string): { tenantId: string; assetId: string; renditionId: string } {
  const match = typeof key === 'string' ? OBJECT_KEY.exec(key) : null;
  if (!match || key !== key.toLowerCase()) throw new DomainError('INVALID_STORAGE_KEY', 'Package key is invalid');
  return { tenantId: match[1]!, assetId: match[2]!, renditionId: match[3]! };
}

export class PostgresPackageStore implements ProtectedPackageStore {
  private readonly pool: Pool;

  constructor(pool: Pool) { this.pool = pool; }

  async put(key: string, pkg: SecurePackage): Promise<PackageReceipt> {
    const { tenantId, assetId, renditionId } = identity(key);
    if (!pkg || pkg.manifest?.identity?.tenantId !== tenantId ||
        pkg.manifest.identity.assetId !== assetId || pkg.manifest.identity.renditionId !== renditionId ||
        pkg.manifest.identity.assetVersion !== '1') {
      throw new DomainError('INVALID_STORAGE_KEY', 'Package identity and key mismatch');
    }
    const body = Buffer.from(JSON.stringify(pkg));
    if (body.length < 1 || body.length > MAX_PACKAGE_BYTES) throw new DomainError('INVALID_PACKAGE', 'Stored package too large');
    const digest = createHash('sha256').update(body).digest();
    const inserted = await withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query(`INSERT INTO drm.package_objects
        (tenant_id, object_key, package_sha256, package_bytes, body)
        VALUES ($1, $2, $3, $4, $5) ON CONFLICT (object_key) DO NOTHING`,
      [tenantId, key, digest, body.length, body]);
      return result.rowCount === 1;
    });
    if (!inserted) throw new DomainError('STORAGE_CONFLICT', 'Package already exists');
    return { sha256: digest.toString('hex'), bytes: body.length };
  }

  async get(key: string, expectedSha256: string, expectedBytes: number): Promise<Buffer> {
    const { tenantId } = identity(key);
    if (typeof expectedSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expectedSha256) ||
        !Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > MAX_PACKAGE_BYTES) {
      throw new DomainError('INVALID_STORAGE_KEY', 'Package retrieval metadata is invalid');
    }
    const row = await withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query<{ body: Buffer; package_sha256: Buffer; package_bytes: number }>(
        'SELECT body, package_sha256, package_bytes FROM drm.package_objects WHERE tenant_id = $1 AND object_key = $2',
        [tenantId, key]);
      return result.rows[0];
    });
    if (!row) throw new DomainError('STORAGE_UNAVAILABLE', 'Package is missing');
    const expected = Buffer.from(expectedSha256, 'hex');
    if (!Buffer.isBuffer(row.body) || row.body.length !== expectedBytes || row.package_bytes !== expectedBytes ||
        !Buffer.isBuffer(row.package_sha256) || row.package_sha256.length !== 32 ||
        !timingSafeEqual(row.package_sha256, expected) ||
        !timingSafeEqual(createHash('sha256').update(row.body).digest(), expected)) {
      throw new DomainError('INVALID_STORAGE_CONTENT', 'Package checksum differs from catalog');
    }
    return Buffer.from(row.body);
  }

  async delete(key: string): Promise<void> {
    const { tenantId } = identity(key);
    await withTenantTransaction(this.pool, tenantId, async (client) => {
      await client.query(`DELETE FROM drm.package_objects o WHERE o.tenant_id = $1 AND o.object_key = $2
        AND NOT EXISTS (SELECT 1 FROM drm.asset_packages ap
          WHERE ap.tenant_id = o.tenant_id AND ap.object_key = o.object_key)`, [tenantId, key]);
    });
  }
}
