import type { Pool } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from '@drm/postgres';

export type LimitedOperation = 'device-challenge' | 'license-issue' | 'asset-publish';

/** PostgreSQL row locks make limits consistent across API replicas. */
export async function consumeUserRateLimit(
  pool: Pool, tenantId: string, userId: string,
  operation: LimitedOperation, perMinute: number,
): Promise<void> {
  if (!Number.isSafeInteger(perMinute) || perMinute < 1 || perMinute > 1000) {
    throw new DomainError('INVALID_RATE_LIMIT', 'Rate limit configuration is invalid');
  }
  await withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query<{ request_count: number }>(
      `INSERT INTO drm.api_rate_windows (tenant_id, user_id, operation, window_start, request_count)
       VALUES ($1, $2, $3, date_trunc('minute', clock_timestamp()), 1)
       ON CONFLICT (tenant_id, user_id, operation, window_start)
       DO UPDATE SET request_count = drm.api_rate_windows.request_count + 1
       WHERE drm.api_rate_windows.request_count < $4
       RETURNING request_count`,
      [tenantId, userId, operation, perMinute],
    );
    if (result.rowCount !== 1) throw new DomainError('RATE_LIMITED', 'Too many requests');
  });
}
