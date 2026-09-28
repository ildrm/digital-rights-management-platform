import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { DomainError } from '@drm/core';
import { withTenantTransaction } from './tenant-transaction.ts';

export interface OutboxEvent {
  readonly id: string;
  readonly tenantId: string;
  readonly eventType: string;
  readonly aggregateId: string;
  readonly payload: Record<string, unknown>;
  readonly attempts: number;
}

export async function appendOutboxEvent(
  client: PoolClient, tenantId: string, eventType: string,
  aggregateId: string, payload: Record<string, unknown>,
): Promise<string> {
  if (!/^[a-z][a-z0-9.]{0,127}$/.test(eventType)) throw new DomainError('INVALID_EVENT', 'Event type is invalid');
  const id = randomUUID();
  await client.query(
    `INSERT INTO drm.outbox_events (tenant_id, id, event_type, aggregate_id, payload)
     VALUES ($1, $2, $3, $4, $5)`,
    [tenantId, id, eventType, aggregateId, payload],
  );
  return id;
}

function worker(value: string): void {
  if (typeof value !== 'string' || value.length < 1 || value.length > 128 || !/^[a-zA-Z0-9._:-]+$/.test(value)) {
    throw new DomainError('INVALID_WORKER', 'Worker identity is invalid');
  }
}

export async function claimOutboxEvents(
  pool: Pool, tenantId: string, workerId: string,
  limit = 25, leaseSeconds = 60,
): Promise<readonly OutboxEvent[]> {
  worker(workerId);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(leaseSeconds) || leaseSeconds < 5 || leaseSeconds > 300) {
    throw new DomainError('INVALID_OUTBOX_LEASE', 'Outbox claim settings are invalid');
  }
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query<{
      id: string; tenant_id: string; event_type: string; aggregate_id: string;
      payload: Record<string, unknown>; attempts: number;
    }>(
      `WITH candidates AS (
         SELECT id FROM drm.outbox_events
         WHERE tenant_id = $1 AND delivered_at IS NULL AND available_at <= clock_timestamp()
           AND (claimed_until IS NULL OR claimed_until < clock_timestamp())
         ORDER BY available_at, created_at, id
         FOR UPDATE SKIP LOCKED LIMIT $3
       )
       UPDATE drm.outbox_events e
       SET claimed_by = $2, claimed_until = clock_timestamp() + ($4 * interval '1 second'), attempts = attempts + 1
       FROM candidates c
       WHERE e.tenant_id = $1 AND e.id = c.id
       RETURNING e.id, e.tenant_id, e.event_type, e.aggregate_id, e.payload, e.attempts`,
      [tenantId, workerId, limit, leaseSeconds],
    );
    return result.rows.map((row) => ({
      id: row.id, tenantId: row.tenant_id, eventType: row.event_type,
      aggregateId: row.aggregate_id, payload: row.payload, attempts: row.attempts,
    }));
  });
}

export async function markOutboxDelivered(pool: Pool, tenantId: string, eventId: string, workerId: string): Promise<boolean> {
  worker(workerId);
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query(
      `UPDATE drm.outbox_events
       SET delivered_at = clock_timestamp(), claimed_by = NULL, claimed_until = NULL
       WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3
         AND claimed_until > clock_timestamp() AND delivered_at IS NULL`,
      [tenantId, eventId, workerId],
    );
    return result.rowCount === 1;
  });
}

export async function releaseOutboxEvent(
  pool: Pool, tenantId: string, eventId: string, workerId: string, retryDelaySeconds: number,
): Promise<boolean> {
  worker(workerId);
  if (!Number.isSafeInteger(retryDelaySeconds) || retryDelaySeconds < 1 || retryDelaySeconds > 3600) {
    throw new DomainError('INVALID_OUTBOX_RETRY', 'Outbox retry delay is invalid');
  }
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query(
      `UPDATE drm.outbox_events
       SET available_at = clock_timestamp() + ($4 * interval '1 second'), claimed_by = NULL, claimed_until = NULL
       WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND delivered_at IS NULL`,
      [tenantId, eventId, workerId, retryDelaySeconds],
    );
    return result.rowCount === 1;
  });
}
