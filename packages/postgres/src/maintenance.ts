import type { Pool } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';

export interface CleanupResult {
  readonly rateWindows: number;
  readonly deviceChallenges: number;
  readonly enrollmentChallenges: number;
}

export async function cleanupTenantEphemera(pool: Pool, tenantId: string, limit = 1000): Promise<CleanupResult> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
    throw new DomainError('INVALID_CLEANUP_LIMIT', 'Cleanup batch limit must be 1–10000');
  }
  return withTenantTransaction(pool, tenantId, async (client) => {
    const rate = await client.query(
      `DELETE FROM drm.api_rate_windows WHERE ctid IN (
         SELECT ctid FROM drm.api_rate_windows
         WHERE tenant_id = $1 AND window_start < clock_timestamp() - interval '24 hours'
         LIMIT $2
       )`, [tenantId, limit]);
    const challenges = await client.query(
      `DELETE FROM drm.device_challenges WHERE ctid IN (
         SELECT ctid FROM drm.device_challenges
         WHERE tenant_id = $1 AND expires_at < clock_timestamp() - interval '24 hours'
         LIMIT $2
       )`, [tenantId, limit]);
    const enrollments = await client.query(
      `DELETE FROM drm.device_enrollment_challenges WHERE ctid IN (
         SELECT ctid FROM drm.device_enrollment_challenges
         WHERE tenant_id = $1 AND expires_at < clock_timestamp() - interval '24 hours'
         LIMIT $2
       )`, [tenantId, limit]);
    return {
      rateWindows: rate.rowCount ?? 0,
      deviceChallenges: challenges.rowCount ?? 0,
      enrollmentChallenges: enrollments.rowCount ?? 0,
    };
  });
}
