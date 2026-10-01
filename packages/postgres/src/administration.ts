import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function id(value: string): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new DomainError('INVALID_REQUEST', 'UUID required');
  return value.toLowerCase();
}

export interface AdminGrantInput {
  readonly tenantId: string;
  readonly actorId: string;
  readonly idempotencyKey: string;
  readonly userId: string;
  readonly assetId: string;
  readonly assetVersion: number;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly source: 'free' | 'organization' | 'trial';
  readonly validUntil: string | null;
}

export class PostgresAdministrationService {
  private readonly pool: Pool;
  constructor(pool: Pool) { this.pool = pool; }

  private async authorized(client: PoolClient, tenantId: string, actorId: string): Promise<void> {
    const actor = await client.query(`SELECT u.id FROM drm.users u JOIN drm.user_roles r
      ON (r.tenant_id,r.user_id) = (u.tenant_id,u.id)
      WHERE u.tenant_id = $1 AND u.id = $2 AND u.status = 'active' AND r.role = 'admin' FOR SHARE OF u`, [tenantId, actorId]);
    if (!actor.rowCount) throw new DomainError('ACCESS_DENIED', 'Active tenant administrator required');
  }

  async provisionUser(tenant: string, actor: string, key: string, subject: string, roles: readonly string[]): Promise<{ userId: string }> {
    const tenantId = id(tenant), actorId = id(actor), userId = id(key);
    if (typeof subject !== 'string' || subject.trim().length < 1 || subject.length > 256 ||
        !Array.isArray(roles) || roles.length < 1 || roles.length > 2 || new Set(roles).size !== roles.length ||
        roles.some((role) => !['customer', 'creator'].includes(role))) {
      throw new DomainError('INVALID_REQUEST', 'Subject and customer/creator roles required');
    }
    const externalSubject = subject.trim();
    const roleSnapshot = [...roles].sort();
    return withTenantTransaction(this.pool, tenantId, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 832902))', [tenantId]);
      await this.authorized(client, tenantId, actorId);
      const existing = await client.query<{ external_subject: string; roles: string[] }>(`SELECT u.external_subject,
        ARRAY(SELECT role FROM drm.user_roles WHERE tenant_id = u.tenant_id AND user_id = u.id ORDER BY role) AS roles
        FROM drm.users u WHERE u.tenant_id = $1 AND u.id = $2`, [tenantId, userId]);
      if (existing.rows[0]) {
        if (existing.rows[0].external_subject !== externalSubject || JSON.stringify(existing.rows[0].roles) !== JSON.stringify(roleSnapshot)) {
          throw new DomainError('IDEMPOTENCY_CONFLICT', 'User key has different account terms');
        }
        return { userId };
      }
      if ((await client.query('SELECT id FROM drm.users WHERE tenant_id = $1 AND external_subject = $2', [tenantId, externalSubject])).rowCount) {
        throw new DomainError('ACCOUNT_EXISTS', 'An account with that subject already exists');
      }
      await client.query("INSERT INTO drm.users(tenant_id,id,external_subject,status) VALUES ($1,$2,$3,'active')", [tenantId, userId, externalSubject]);
      for (const role of roleSnapshot) await client.query('INSERT INTO drm.user_roles(tenant_id,user_id,role) VALUES ($1,$2,$3)', [tenantId, userId, role]);
      await this.audit(client, tenantId, actorId, 'identity.user_provisioned', { userId, roles: roleSnapshot });
      return { userId };
    });
  }

  async setUserStatus(tenant: string, actor: string, user: string, status: string): Promise<void> {
    const tenantId = id(tenant), actorId = id(actor), userId = id(user);
    if (!['active', 'suspended', 'revoked'].includes(status)) throw new DomainError('INVALID_REQUEST', 'Invalid user status');
    await withTenantTransaction(this.pool, tenantId, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 832902))', [tenantId]);
      await this.authorized(client, tenantId, actorId);
      const target = await client.query<{ status: string }>('SELECT status FROM drm.users WHERE tenant_id = $1 AND id = $2 FOR UPDATE', [tenantId, userId]);
      if (!target.rows[0]) throw new DomainError('ACCOUNT_NOT_FOUND', 'Tenant account not found');
      if (target.rows[0].status === status) return;
      if (target.rows[0].status === 'revoked') throw new DomainError('ACCOUNT_REVOKED', 'Revoked accounts cannot be restored');
      if (status !== 'active' && (await client.query("SELECT user_id FROM drm.user_roles WHERE tenant_id = $1 AND user_id = $2 AND role = 'admin'", [tenantId, userId])).rowCount) {
        const count = await client.query<{ total: number }>(`SELECT count(*)::integer AS total FROM drm.user_roles r JOIN drm.users u
          ON (u.tenant_id,u.id) = (r.tenant_id,r.user_id) WHERE r.tenant_id = $1 AND r.role = 'admin' AND u.status = 'active'`, [tenantId]);
        if (count.rows[0]!.total <= 1) throw new DomainError('LAST_ADMIN', 'The last active administrator cannot be suspended or revoked');
      }
      await client.query('UPDATE drm.users SET status = $3 WHERE tenant_id = $1 AND id = $2', [tenantId, userId, status]);
      if (status !== 'active') {
        await client.query(`UPDATE drm.licenses l SET revoked_at = clock_timestamp() FROM drm.entitlements e
          WHERE (e.tenant_id,e.id) = (l.tenant_id,l.entitlement_id) AND e.tenant_id = $1 AND e.subject_user_id = $2 AND l.revoked_at IS NULL`, [tenantId, userId]);
        await client.query(`UPDATE drm.device_activations d SET released_at = clock_timestamp() FROM drm.entitlements e
          WHERE (e.tenant_id,e.id) = (d.tenant_id,d.entitlement_id) AND e.tenant_id = $1 AND e.subject_user_id = $2 AND d.released_at IS NULL`, [tenantId, userId]);
      }
      await this.audit(client, tenantId, actorId, 'identity.user_status_changed', { userId, status });
    });
  }

  async grant(input: AdminGrantInput): Promise<{ entitlementId: string }> {
    const tenantId = id(input.tenantId), actorId = id(input.actorId), entitlementId = id(input.idempotencyKey);
    const userId = id(input.userId), assetId = id(input.assetId), policyId = id(input.policyId);
    if (!Number.isSafeInteger(input.assetVersion) || input.assetVersion < 1 || !Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1 ||
        !['free', 'organization', 'trial'].includes(input.source) || input.source === 'trial' && input.validUntil === null || input.validUntil !== null &&
        (typeof input.validUntil !== 'string' || !Number.isFinite(Date.parse(input.validUntil)) || new Date(input.validUntil).toISOString() !== input.validUntil)) {
      throw new DomainError('INVALID_REQUEST', 'Invalid grant terms');
    }
    const terms = { ...input };
    return withTenantTransaction(this.pool, tenantId, async (client) => {
      await this.authorized(client, tenantId, actorId);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 832903))', [entitlementId]);
      const existing = await client.query<{ subject_user_id: string; asset_id: string; asset_version: number; policy_id: string; policy_version: number; source: string; valid_until: Date | null }>(
        'SELECT * FROM drm.entitlements WHERE tenant_id = $1 AND id = $2', [tenantId, entitlementId]);
      if (existing.rows[0]) {
        const row = existing.rows[0];
        if (row.subject_user_id !== userId || row.asset_id !== assetId || row.asset_version !== terms.assetVersion ||
            row.policy_id !== policyId || row.policy_version !== terms.policyVersion || row.source !== terms.source ||
            (row.valid_until?.toISOString() ?? null) !== terms.validUntil) throw new DomainError('IDEMPOTENCY_CONFLICT', 'Grant key has different terms');
        return { entitlementId };
      }
      if (terms.validUntil !== null && Date.parse(terms.validUntil) <= Date.now()) throw new DomainError('INVALID_REQUEST', 'Grant expiry must be in the future');
      const recipient = await client.query("SELECT id FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR SHARE", [tenantId, userId]);
      const asset = await client.query(`SELECT a.id FROM drm.assets a JOIN drm.policies p ON (p.tenant_id,p.asset_id) = (a.tenant_id,a.id)
        WHERE a.tenant_id = $1 AND a.id = $2 AND a.status = 'published' AND p.id = $3 AND p.version = $4
          AND EXISTS (SELECT 1 FROM drm.asset_packages ap WHERE ap.tenant_id = a.tenant_id AND ap.asset_id = a.id AND ap.asset_version = $5)
        FOR SHARE OF a`, [tenantId, assetId, policyId, terms.policyVersion, terms.assetVersion]);
      if (!recipient.rowCount || !asset.rowCount) throw new DomainError('ACCESS_DENIED', 'Active recipient and published package required');
      await client.query(`INSERT INTO drm.entitlements
        (tenant_id,id,subject_user_id,asset_id,asset_version,policy_id,policy_version,source,status,valid_from,valid_until)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',clock_timestamp(),$9)`,
      [tenantId, entitlementId, userId, assetId, terms.assetVersion, policyId, terms.policyVersion, terms.source, terms.validUntil]);
      await this.audit(client, tenantId, actorId, 'entitlement.admin_granted', { entitlementId, userId, assetId, source: terms.source });
      return { entitlementId };
    });
  }

  async revokeGrant(tenant: string, actor: string, grant: string): Promise<void> {
    const tenantId = id(tenant), actorId = id(actor), entitlementId = id(grant);
    await withTenantTransaction(this.pool, tenantId, async (client) => {
      await this.authorized(client, tenantId, actorId);
      const result = await client.query<{ status: string }>('SELECT status FROM drm.entitlements WHERE tenant_id = $1 AND id = $2 FOR UPDATE', [tenantId, entitlementId]);
      if (!result.rows[0]) throw new DomainError('ENTITLEMENT_NOT_FOUND', 'Tenant entitlement not found');
      if (result.rows[0].status === 'revoked') return;
      await client.query("UPDATE drm.entitlements SET status = 'revoked' WHERE tenant_id = $1 AND id = $2", [tenantId, entitlementId]);
      await client.query('UPDATE drm.licenses SET revoked_at = clock_timestamp() WHERE tenant_id = $1 AND entitlement_id = $2 AND revoked_at IS NULL', [tenantId, entitlementId]);
      await client.query('UPDATE drm.device_activations SET released_at = clock_timestamp() WHERE tenant_id = $1 AND entitlement_id = $2 AND released_at IS NULL', [tenantId, entitlementId]);
      await this.audit(client, tenantId, actorId, 'entitlement.admin_revoked', { entitlementId });
    });
  }

  private async audit(client: PoolClient, tenantId: string, actorId: string, event: string, details: Record<string, unknown>): Promise<void> {
    await client.query('INSERT INTO drm.audit_events(tenant_id,id,actor_id,event_type,details) VALUES ($1,$2,$3,$4,$5)', [tenantId, randomUUID(), actorId, event, details]);
    await client.query('INSERT INTO drm.outbox_events(tenant_id,id,aggregate_id,event_type,payload) VALUES ($1,$2,$3,$4,$5)', [tenantId, randomUUID(), actorId, event, details]);
  }
}
