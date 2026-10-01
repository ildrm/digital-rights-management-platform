import type { Pool } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface CatalogPage<T> {
  readonly items: T[];
  readonly nextCursor?: string;
}

export interface OwnedAsset {
  readonly assetId: string;
  readonly version: number;
  readonly renditionId: string;
  readonly mimeType: string;
  readonly createdAt: string;
}

export interface LibraryAsset extends OwnedAsset {
  readonly entitlementId: string;
  readonly validUntil: string | null;
}

function pageArguments(tenantId: string, userId: string, limit: number, cursor?: string): string {
  if (![tenantId, userId].every((value) => typeof value === 'string' && UUID.test(value)) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      cursor !== undefined && (typeof cursor !== 'string' || !UUID.test(cursor))) {
    throw new DomainError('INVALID_REQUEST', 'Invalid catalog page arguments');
  }
  return cursor?.toLowerCase() ?? '00000000-0000-0000-0000-000000000000';
}

export class PostgresCatalog {
  private readonly pool: Pool;

  constructor(pool: Pool) { this.pool = pool; }

  async owned(tenantId: string, ownerId: string, limit = 20, cursor?: string): Promise<CatalogPage<OwnedAsset>> {
    const after = pageArguments(tenantId, ownerId, limit, cursor);
    const rows = await withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query<{
        asset_id: string; asset_version: number; rendition_id: string; mime_type: string; created_at: Date;
      }>(`SELECT a.id AS asset_id, ap.asset_version, ap.rendition_id, ap.mime_type, a.created_at
          FROM drm.assets a JOIN drm.users u
            ON u.tenant_id = a.tenant_id AND u.id = a.owner_user_id AND u.status = 'active'
          JOIN LATERAL (
            SELECT asset_version, rendition_id, mime_type FROM drm.asset_packages
            WHERE tenant_id = a.tenant_id AND asset_id = a.id
            ORDER BY asset_version DESC, rendition_id LIMIT 1
          ) ap ON true
          WHERE a.tenant_id = $1 AND a.owner_user_id = $2 AND a.status = 'published'
            AND a.id > $3
          ORDER BY a.id
          LIMIT $4`, [tenantId, ownerId, after, limit + 1]);
      return result.rows;
    });
    // Return one representative rendition per asset so the UUID cursor remains stable.
    const items = rows.slice(0, limit).map((row) => ({
      assetId: row.asset_id, version: row.asset_version, renditionId: row.rendition_id,
      mimeType: row.mime_type, createdAt: row.created_at.toISOString(),
    }));
    return { items, ...(rows.length > limit ? { nextCursor: items.at(-1)!.assetId } : {}) };
  }

  async library(tenantId: string, userId: string, limit = 20, cursor?: string): Promise<CatalogPage<LibraryAsset>> {
    const after = pageArguments(tenantId, userId, limit, cursor);
    const rows = await withTenantTransaction(this.pool, tenantId, async (client) => {
      const result = await client.query<{
        entitlement_id: string; asset_id: string; asset_version: number; rendition_id: string;
        mime_type: string; created_at: Date; valid_until: Date | null;
      }>(`SELECT e.id AS entitlement_id, e.asset_id, e.asset_version, ap.rendition_id,
            ap.mime_type, a.created_at, e.valid_until
          FROM drm.entitlements e
          JOIN drm.users u ON u.tenant_id = e.tenant_id
            AND u.id = e.subject_user_id AND u.status = 'active'
          JOIN drm.assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
          JOIN LATERAL (
            SELECT ap.rendition_id, ap.mime_type
            FROM drm.asset_packages ap
            JOIN drm.rendition_keys rk ON rk.tenant_id = ap.tenant_id
              AND rk.asset_id = ap.asset_id AND rk.asset_version = ap.asset_version
              AND rk.rendition_id = ap.rendition_id
            WHERE ap.tenant_id = e.tenant_id AND ap.asset_id = e.asset_id
              AND ap.asset_version = e.asset_version AND rk.status = 'active'
            ORDER BY ap.rendition_id LIMIT 1
          ) ap ON true
          WHERE e.tenant_id = $1 AND e.subject_user_id = $2 AND e.id > $3
            AND e.status = 'active' AND e.valid_from <= clock_timestamp()
            AND (e.valid_until IS NULL OR e.valid_until > clock_timestamp())
            AND a.status = 'published'
          ORDER BY e.id LIMIT $4`, [tenantId, userId, after, limit + 1]);
      return result.rows;
    });
    const items = rows.slice(0, limit).map((row) => ({
      entitlementId: row.entitlement_id, assetId: row.asset_id, version: row.asset_version,
      renditionId: row.rendition_id, mimeType: row.mime_type,
      createdAt: row.created_at.toISOString(), validUntil: row.valid_until?.toISOString() ?? null,
    }));
    return { items, ...(rows.length > limit ? { nextCursor: items.at(-1)!.entitlementId } : {}) };
  }
}
