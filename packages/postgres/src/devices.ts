import { createHash, createPublicKey, randomBytes, randomUUID, verify, type KeyObject } from 'node:crypto';
import type { Pool } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';
import { appendOutboxEvent } from './outbox.ts';

const DEVICE_CLASS = /^[a-z][a-z0-9-]{0,31}$/;

function publicKey(publicKeyPem: string): { key: KeyObject; fingerprint: Buffer; canonicalPem: string } {
  if (typeof publicKeyPem !== 'string' || publicKeyPem.length < 64 || publicKeyPem.length > 2048) {
    throw new DomainError('INVALID_DEVICE_KEY', 'Ed25519 public key PEM required');
  }
  try {
    if (!publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n')) {
      throw new DomainError('INVALID_DEVICE_KEY', 'Public-only SPKI PEM required');
    }
    const key = createPublicKey(publicKeyPem);
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new DomainError('INVALID_DEVICE_KEY', 'Ed25519 public key required');
    const canonicalPem = key.export({ type: 'spki', format: 'pem' }).toString();
    if (publicKeyPem.trimEnd() !== canonicalPem.trimEnd()) {
      throw new DomainError('INVALID_DEVICE_KEY', 'One canonical public key required');
    }
    return { key, canonicalPem, fingerprint: createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest() };
  } catch {
    throw new DomainError('INVALID_DEVICE_KEY', 'Ed25519 public key PEM required');
  }
}

function deviceClass(value: string): void {
  if (typeof value !== 'string' || !DEVICE_CLASS.test(value)) throw new DomainError('INVALID_DEVICE_CLASS', 'Device class must be a short lowercase identifier');
}

function hashChallenge(challenge: string): Buffer {
  return createHash('sha256').update(challenge, 'utf8').digest();
}

export async function issueDeviceEnrollmentChallenge(
  pool: Pool, tenantId: string, userId: string, publicKeyPem: string, deviceClassName: string,
): Promise<string> {
  const { fingerprint } = publicKey(publicKeyPem);
  deviceClass(deviceClassName);
  const challenge = randomBytes(32).toString('base64url');
  await withTenantTransaction(pool, tenantId, async (client) => {
    const user = await client.query(
      "SELECT id FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE",
      [tenantId, userId],
    );
    if (user.rowCount !== 1) throw new DomainError('ACCESS_DENIED', 'Active account required');
    const pending = await client.query<{ count: number }>(
      `SELECT count(*)::integer AS count FROM drm.device_enrollment_challenges
       WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp()`,
      [tenantId, userId],
    );
    if ((pending.rows[0]?.count ?? 0) >= 3) throw new DomainError('CHALLENGE_LIMIT', 'Too many pending enrollment challenges');
    await client.query(
      `INSERT INTO drm.device_enrollment_challenges
       (tenant_id, id, user_id, public_key_sha256, device_class, challenge_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp() + interval '2 minutes')`,
      [tenantId, randomUUID(), userId, fingerprint, deviceClassName, hashChallenge(challenge)],
    );
  });
  return challenge;
}

export interface RegisterDeviceInput {
  readonly tenantId: string;
  readonly userId: string;
  readonly publicKeyPem: string;
  readonly deviceClass: string;
  readonly challenge: string;
  readonly signature: string;
}

export async function registerDevice(pool: Pool, input: RegisterDeviceInput): Promise<string> {
  const { key, fingerprint, canonicalPem } = publicKey(input.publicKeyPem);
  deviceClass(input.deviceClass);
  if (typeof input.challenge !== 'string' || input.challenge.length < 16 || input.challenge.length > 256 ||
      typeof input.signature !== 'string' || input.signature.length < 1 || input.signature.length > 256 ||
      !verify(null, Buffer.from(input.challenge, 'utf8'), key, Buffer.from(input.signature, 'base64url'))) {
    throw new DomainError('DEVICE_PROOF_INVALID', 'Device possession proof is invalid');
  }
  return withTenantTransaction(pool, input.tenantId, async (client) => {
    const user = await client.query(
      "SELECT id FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE",
      [input.tenantId, input.userId],
    );
    if (user.rowCount !== 1) throw new DomainError('ACCESS_DENIED', 'Active account required');
    const consumed = await client.query(
      `UPDATE drm.device_enrollment_challenges SET consumed_at = clock_timestamp()
       WHERE tenant_id = $1 AND user_id = $2 AND public_key_sha256 = $3 AND device_class = $4
         AND challenge_hash = $5 AND consumed_at IS NULL AND expires_at > clock_timestamp()
       RETURNING id`,
      [input.tenantId, input.userId, fingerprint, input.deviceClass, hashChallenge(input.challenge)],
    );
    if (consumed.rowCount !== 1) throw new DomainError('DEVICE_PROOF_REPLAY', 'Enrollment challenge expired or consumed');
    const active = await client.query<{ count: number }>(
      'SELECT count(*)::integer AS count FROM drm.devices WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL',
      [input.tenantId, input.userId],
    );
    if ((active.rows[0]?.count ?? 0) >= 10) throw new DomainError('DEVICE_LIMIT', 'Device enrollment limit reached');
    const id = randomUUID();
    const inserted = await client.query(
      `INSERT INTO drm.devices (tenant_id, id, user_id, public_key_pem, public_key_sha256, trust_level, device_class)
       VALUES ($1, $2, $3, $4, $5, 'software', $6)
       ON CONFLICT DO NOTHING RETURNING id`,
      [input.tenantId, id, input.userId, canonicalPem, fingerprint, input.deviceClass],
    );
    if (inserted.rowCount !== 1) throw new DomainError('DEVICE_ALREADY_REGISTERED', 'This key is already registered');
    await client.query(
      `INSERT INTO drm.audit_events (tenant_id, id, actor_id, event_type, details)
       VALUES ($1, $2, $3, 'device.registered', $4)`,
      [input.tenantId, randomUUID(), input.userId, { deviceId: id, deviceClass: input.deviceClass }],
    );
    await appendOutboxEvent(client, input.tenantId, 'device.registered', id, { userId: input.userId, deviceClass: input.deviceClass });
    return id;
  });
}

export async function revokeOwnedDevice(pool: Pool, tenantId: string, userId: string, deviceId: string): Promise<void> {
  await withTenantTransaction(pool, tenantId, async (client) => {
    const updated = await client.query(
      `UPDATE drm.devices SET revoked_at = clock_timestamp()
       WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND revoked_at IS NULL
       RETURNING id`,
      [tenantId, deviceId, userId],
    );
    if (updated.rowCount !== 1) throw new DomainError('DEVICE_NOT_FOUND', 'Active owned device required');
    await client.query(
      `UPDATE drm.device_activations SET released_at = clock_timestamp()
       WHERE tenant_id = $1 AND device_id = $2 AND released_at IS NULL`,
      [tenantId, deviceId],
    );
    await client.query(
      `UPDATE drm.licenses SET revoked_at = clock_timestamp()
       WHERE tenant_id = $1 AND device_id = $2 AND revoked_at IS NULL`,
      [tenantId, deviceId],
    );
    await client.query(
      `INSERT INTO drm.audit_events (tenant_id, id, actor_id, event_type, details)
       VALUES ($1, $2, $3, 'device.revoked', $4)`,
      [tenantId, randomUUID(), userId, { deviceId }],
    );
    await appendOutboxEvent(client, tenantId, 'device.revoked', deviceId, { userId });
  });
}
