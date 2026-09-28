import { createHash, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import {
  canonicalJson, compilePolicy, DomainError, LicenseIssuer, type Action,
  type Device, type DeviceProof, type Entitlement, type LicenseSigner,
  type Policy, type SignedLicense,
} from '@drm/core';
import { PostgresChallengeStore } from './challenges.ts';
import { withTenantTransaction } from './tenant-transaction.ts';
import { appendOutboxEvent } from './outbox.ts';

export interface DatabaseLicenseRequest {
  readonly tenantId: string;
  readonly authenticatedUserId: string;
  readonly entitlementId: string;
  readonly deviceId: string;
  readonly renditionId: string;
  readonly action: Action;
  readonly proof: DeviceProof;
  readonly requestedSeconds: number;
}

export interface KeyReferenceVerifier {
  assertActive(reference: string, tenantId: string, assetId: string, assetVersion: number, renditionId: string): Promise<void>;
}

interface EntitlementRow {
  tenant_id: string;
  id: string;
  subject_user_id: string;
  asset_id: string;
  asset_version: number;
  policy_id: string;
  policy_version: number;
  source: Entitlement['source'];
  status: Entitlement['status'];
  valid_from: Date;
  valid_until: Date | null;
  user_status: string;
  asset_status: string;
}

interface DeviceRow {
  id: string;
  tenant_id: string;
  user_id: string;
  public_key_pem: string;
  trust_level: Device['trust'];
  device_class: string;
  revoked_at: Date | null;
}

interface PolicyRow {
  document: Policy;
  digest: Buffer;
}

interface RenditionRow {
  target: string;
  key_reference: string;
}

export class PostgresLicenseService {
  private readonly pool: Pool;
  private readonly signer: LicenseSigner;
  private readonly keys: KeyReferenceVerifier;
  private readonly issuerName: string;
  private readonly trustedTime: () => string;

  constructor(pool: Pool, signer: LicenseSigner, keys: KeyReferenceVerifier, issuerName: string, trustedTime: () => string) {
    this.pool = pool;
    this.signer = signer;
    this.keys = keys;
    this.issuerName = issuerName;
    this.trustedTime = trustedTime;
  }

  async issue(request: DatabaseLicenseRequest): Promise<SignedLicense> {
    return withTenantTransaction(this.pool, request.tenantId, async (client) => {
      // Lock this grant so two concurrent issuances cannot both claim its last device seat.
      const grantResult = await client.query<EntitlementRow>(
        `SELECT e.*, u.status AS user_status, a.status AS asset_status
         FROM drm.entitlements e
         JOIN drm.users u ON u.tenant_id = e.tenant_id AND u.id = e.subject_user_id
         JOIN drm.assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
         WHERE e.tenant_id = $1 AND e.id = $2 AND e.subject_user_id = $3
         FOR UPDATE OF e, u, a`,
        [request.tenantId, request.entitlementId, request.authenticatedUserId],
      );
      const row = grantResult.rows[0];
      if (!row || row.user_status !== 'active' || row.asset_status !== 'published') throw new DomainError('ACCESS_DENIED', 'Grant, account, or asset is unavailable');

      const deviceResult = await client.query<DeviceRow>(
        `SELECT id, tenant_id, user_id, public_key_pem, trust_level, device_class, revoked_at
         FROM drm.devices WHERE tenant_id = $1 AND id = $2 AND user_id = $3
         FOR UPDATE`,
        [request.tenantId, request.deviceId, request.authenticatedUserId],
      );
      const deviceRow = deviceResult.rows[0];
      if (!deviceRow || deviceRow.revoked_at) throw new DomainError('ACCESS_DENIED', 'Device unavailable');

      const policyResult = await client.query<PolicyRow>(
        'SELECT document, digest FROM drm.policies WHERE tenant_id = $1 AND id = $2 AND version = $3 AND asset_id = $4',
        [request.tenantId, row.policy_id, row.policy_version, row.asset_id],
      );
      const policy = policyResult.rows[0]?.document;
      if (!policy || policy.tenantId !== request.tenantId || policy.assetId !== row.asset_id || policy.id !== row.policy_id || policy.version !== row.policy_version) {
        throw new DomainError('POLICY_MISMATCH', 'Stored policy does not match entitlement');
      }
      const compiled = compilePolicy(policy, 'secureViewer');
      if (compiled.sourceDigest !== policyResult.rows[0]?.digest.toString('hex')) throw new DomainError('POLICY_MISMATCH', 'Stored policy digest mismatch');
      if (policy.duties.length > 0 || policy.constraints.maxConcurrentSessions !== undefined || policy.constraints.maxUses !== undefined ||
          policy.constraints.maxExports !== undefined || policy.constraints.territories !== undefined || policy.constraints.organizationId !== undefined ||
          policy.constraints.requiredRole !== undefined || policy.constraints.feature !== undefined || policy.constraints.creditLimit !== undefined) {
        throw new DomainError('UNSUPPORTED_POLICY', 'This issuance path cannot verify all policy duties or constraints');
      }

      const renditionResult = await client.query<RenditionRow>(
        `SELECT target, key_reference FROM drm.rendition_keys
         WHERE tenant_id = $1 AND asset_id = $2 AND asset_version = $3 AND rendition_id = $4 AND status = 'active'
         FOR SHARE`,
        [request.tenantId, row.asset_id, row.asset_version, request.renditionId],
      );
      const rendition = renditionResult.rows[0];
      if (!rendition || rendition.target !== 'secureViewer') throw new DomainError('RENDITION_UNAVAILABLE', 'Rendition cannot be licensed by this service');
      await this.keys.assertActive(rendition.key_reference, request.tenantId, row.asset_id, row.asset_version, request.renditionId);

      const countResult = await client.query<{ count: number }>(
        `SELECT count(*)::integer AS count FROM drm.device_activations da
         JOIN drm.devices d ON d.tenant_id = da.tenant_id AND d.id = da.device_id
         WHERE da.tenant_id = $1 AND da.entitlement_id = $2 AND da.device_id <> $3
           AND da.released_at IS NULL AND d.revoked_at IS NULL`,
        [request.tenantId, row.id, request.deviceId],
      );
      const device: Device = {
        id: deviceRow.id, tenantId: deviceRow.tenant_id, userId: deviceRow.user_id,
        publicKeyPem: deviceRow.public_key_pem, trust: deviceRow.trust_level,
        deviceClass: deviceRow.device_class,
      };
      const entitlement: Entitlement = {
        id: row.id, tenantId: row.tenant_id,
        subject: { kind: 'user', id: row.subject_user_id, tenantId: row.tenant_id },
        assetId: row.asset_id, assetVersion: String(row.asset_version),
        policyId: row.policy_id, policyVersion: row.policy_version,
        source: row.source, status: row.status, validFrom: row.valid_from.toISOString(),
        ...(row.valid_until ? { validUntil: row.valid_until.toISOString() } : {}),
      };
      const issuer = new LicenseIssuer(this.signer, new PostgresChallengeStore(client, request.tenantId), this.trustedTime);
      const license = await issuer.issue({
        principal: entitlement.subject, device, entitlement, policy,
        assetVersion: entitlement.assetVersion, action: request.action,
        context: {
          now: this.trustedTime(), territory: '', online: true, roles: [],
          activeDeviceCount: countResult.rows[0]?.count ?? 0, activeSessionCount: 0,
          useCount: 0, exportCount: 0, creditsUsed: 0, fulfilledDuties: [],
        },
        deviceProof: request.proof, renditionId: request.renditionId, keyReference: rendition.key_reference,
        issuer: this.issuerName, requestedSeconds: request.requestedSeconds,
      });
      await client.query(
        `INSERT INTO drm.device_activations (tenant_id, entitlement_id, device_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, entitlement_id, device_id)
         DO UPDATE SET released_at = NULL`,
        [request.tenantId, row.id, request.deviceId],
      );
      const digest = createHash('sha256').update(canonicalJson(license.claims)).digest();
      await client.query(
        `INSERT INTO drm.licenses
         (tenant_id, id, entitlement_id, device_id, policy_id, policy_version, issued_at, expires_at, claims_sha256)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [request.tenantId, license.claims.licenseId, row.id, request.deviceId, row.policy_id, row.policy_version,
          license.claims.issuedAt, license.claims.expiresAt, digest],
      );
      await client.query(
        `INSERT INTO drm.audit_events (tenant_id, id, actor_id, event_type, details)
         VALUES ($1, $2, $3, 'license.issued', $4)`,
        [request.tenantId, randomUUID(), request.authenticatedUserId, {
          licenseId: license.claims.licenseId, assetId: row.asset_id,
          deviceId: request.deviceId, action: request.action,
        }],
      );
      await appendOutboxEvent(client, request.tenantId, 'license.issued', license.claims.licenseId, {
        entitlementId: row.id, deviceId: request.deviceId, assetId: row.asset_id,
      });
      return license;
    });
  }
}
