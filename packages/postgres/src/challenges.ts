import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { DomainError, type ChallengeStore } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';

function challengeHash(challenge: string): Buffer {
  return createHash('sha256').update(challenge, 'utf8').digest();
}

export class PostgresChallengeStore implements ChallengeStore {
  private readonly client: PoolClient;
  private readonly transactionTenantId: string;

  constructor(client: PoolClient, transactionTenantId: string) {
    this.client = client;
    this.transactionTenantId = transactionTenantId.toLowerCase();
  }

  async consume(tenantId: string, deviceId: string, challenge: string): Promise<boolean> {
    if (typeof tenantId !== 'string' || tenantId.toLowerCase() !== this.transactionTenantId) return false;
    if (challenge.length < 16 || challenge.length > 256) return false;
    const result = await this.client.query(
      `UPDATE drm.device_challenges
       SET consumed_at = clock_timestamp()
       WHERE tenant_id = $1 AND device_id = $2 AND challenge_hash = $3
         AND consumed_at IS NULL AND expires_at > clock_timestamp()
       RETURNING id`,
      [tenantId, deviceId, challengeHash(challenge)],
    );
    return result.rowCount === 1;
  }
}

export async function issueDeviceChallenge(pool: Pool, tenantId: string, userId: string, deviceId: string, ttlSeconds = 120): Promise<string> {
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 300) {
    throw new DomainError('INVALID_CHALLENGE_TTL', 'Challenge lifetime must be 30–300 seconds');
  }
  const challenge = randomBytes(32).toString('base64url');
  await withTenantTransaction(pool, tenantId, async (client) => {
    const device = await client.query(
      `SELECT id FROM drm.devices
       WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND revoked_at IS NULL
       FOR UPDATE`,
      [tenantId, deviceId, userId],
    );
    if (device.rowCount !== 1) throw new DomainError('DEVICE_NOT_FOUND', 'Device is unavailable for this user and tenant');
    const pending = await client.query<{ count: number }>(
      `SELECT count(*)::integer AS count FROM drm.device_challenges
       WHERE tenant_id = $1 AND device_id = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp()`,
      [tenantId, deviceId],
    );
    if ((pending.rows[0]?.count ?? 0) >= 3) throw new DomainError('CHALLENGE_LIMIT', 'Too many pending device challenges');
    await client.query(
      `INSERT INTO drm.device_challenges (tenant_id, id, device_id, challenge_hash, expires_at)
       VALUES ($1, $2, $3, $4, clock_timestamp() + ($5 * interval '1 second'))`,
      [tenantId, randomUUID(), deviceId, challengeHash(challenge), ttlSeconds],
    );
  });
  return challenge;
}
