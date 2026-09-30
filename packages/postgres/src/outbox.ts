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
  readonly claimToken: string;
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
  limit = 25, leaseSeconds = 60, maxAttempts = 8,
): Promise<readonly OutboxEvent[]> {
  worker(workerId);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(leaseSeconds) || leaseSeconds < 5 || leaseSeconds > 300 ||
      !Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 32) {
    throw new DomainError('INVALID_OUTBOX_LEASE', 'Outbox claim settings are invalid');
  }
  return withTenantTransaction(pool, tenantId, async (client) => {
    const exhausted = await client.query<{ id: string }>(
      `WITH expired AS (
         SELECT id FROM drm.outbox_events
         WHERE tenant_id = $1 AND delivered_at IS NULL AND dead_lettered_at IS NULL
           AND attempts >= $2 AND (claimed_until IS NULL OR claimed_until < clock_timestamp())
         ORDER BY available_at, created_at, id
         FOR UPDATE SKIP LOCKED LIMIT 1000
       )
       UPDATE drm.outbox_events e
       SET dead_lettered_at = clock_timestamp(), last_error_code = 'ATTEMPTS_EXHAUSTED',
           claimed_by = NULL, claimed_until = NULL, claim_token = NULL
       FROM expired x WHERE e.tenant_id = $1 AND e.id = x.id RETURNING e.id`,
      [tenantId, maxAttempts],
    );
    for (const row of exhausted.rows) {
      await client.query(
        `INSERT INTO drm.audit_events (tenant_id, id, event_type, details)
         VALUES ($1, $2, 'outbox.dead_lettered', $3)`,
        [tenantId, randomUUID(), { eventId: row.id, errorCode: 'ATTEMPTS_EXHAUSTED' }],
      );
    }
    const result = await client.query<{
      id: string; tenant_id: string; event_type: string; aggregate_id: string;
      payload: Record<string, unknown>; attempts: number; claim_token: string;
    }>(
      `WITH candidates AS (
         SELECT id FROM drm.outbox_events
         WHERE tenant_id = $1 AND delivered_at IS NULL AND dead_lettered_at IS NULL
           AND available_at <= clock_timestamp()
           AND (claimed_until IS NULL OR claimed_until < clock_timestamp()) AND attempts < $5
         ORDER BY available_at, created_at, id
         FOR UPDATE SKIP LOCKED LIMIT $3
       )
       UPDATE drm.outbox_events e
       SET claimed_by = $2, claimed_until = clock_timestamp() + ($4 * interval '1 second'),
           claim_token = gen_random_uuid(), attempts = attempts + 1
       FROM candidates c
       WHERE e.tenant_id = $1 AND e.id = c.id
       RETURNING e.id, e.tenant_id, e.event_type, e.aggregate_id, e.payload, e.attempts, e.claim_token`,
      [tenantId, workerId, limit, leaseSeconds, maxAttempts],
    );
    return result.rows.map((row) => ({
      id: row.id, tenantId: row.tenant_id, eventType: row.event_type,
      aggregateId: row.aggregate_id, payload: row.payload, attempts: row.attempts, claimToken: row.claim_token,
    }));
  });
}

export async function markOutboxDelivered(pool: Pool, tenantId: string, eventId: string, workerId: string, claimToken: string): Promise<boolean> {
  worker(workerId);
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query(
      `UPDATE drm.outbox_events
       SET delivered_at = clock_timestamp(), claimed_by = NULL, claimed_until = NULL, claim_token = NULL
       WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND claim_token = $4
         AND claimed_until > clock_timestamp() AND delivered_at IS NULL AND dead_lettered_at IS NULL`,
      [tenantId, eventId, workerId, claimToken],
    );
    return result.rowCount === 1;
  });
}

export async function releaseOutboxEvent(
  pool: Pool, tenantId: string, eventId: string, workerId: string, claimToken: string, retryDelaySeconds: number,
  errorCode: string | null = null,
): Promise<boolean> {
  worker(workerId);
  if (!Number.isSafeInteger(retryDelaySeconds) || retryDelaySeconds < 1 || retryDelaySeconds > 3600) {
    throw new DomainError('INVALID_OUTBOX_RETRY', 'Outbox retry delay is invalid');
  }
  if (errorCode !== null && !/^[A-Z][A-Z0-9_]{0,127}$/.test(errorCode)) {
    throw new DomainError('INVALID_OUTBOX_ERROR', 'Outbox error code is invalid');
  }
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query(
      `UPDATE drm.outbox_events
       SET available_at = clock_timestamp() + ($5 * interval '1 second'),
           last_error_code = $6, claimed_by = NULL, claimed_until = NULL, claim_token = NULL
       WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND claim_token = $4
         AND claimed_until > clock_timestamp() AND delivered_at IS NULL AND dead_lettered_at IS NULL`,
      [tenantId, eventId, workerId, claimToken, retryDelaySeconds, errorCode],
    );
    return result.rowCount === 1;
  });
}

export async function deadLetterOutboxEvent(
  pool: Pool, tenantId: string, eventId: string, workerId: string, claimToken: string, errorCode: string,
): Promise<boolean> {
  worker(workerId);
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(errorCode)) {
    throw new DomainError('INVALID_OUTBOX_ERROR', 'Outbox error code is invalid');
  }
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query(
      `UPDATE drm.outbox_events
       SET dead_lettered_at = clock_timestamp(), last_error_code = $5,
           claimed_by = NULL, claimed_until = NULL, claim_token = NULL
       WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND claim_token = $4
         AND claimed_until > clock_timestamp() AND delivered_at IS NULL AND dead_lettered_at IS NULL`,
      [tenantId, eventId, workerId, claimToken, errorCode],
    );
    if (result.rowCount === 1) {
      await client.query(
        `INSERT INTO drm.audit_events (tenant_id, id, event_type, details)
         VALUES ($1, $2, 'outbox.dead_lettered', $3)`,
        [tenantId, randomUUID(), { eventId, errorCode }],
      );
    }
    return result.rowCount === 1;
  });
}

export async function requeueDeadLetterOutboxEvent(pool: Pool, tenantId: string, eventId: string): Promise<boolean> {
  return withTenantTransaction(pool, tenantId, async (client) => {
    const result = await client.query(
      `UPDATE drm.outbox_events
       SET dead_lettered_at = NULL, last_error_code = NULL, attempts = 0,
           available_at = clock_timestamp()
       WHERE tenant_id = $1 AND id = $2 AND dead_lettered_at IS NOT NULL
         AND delivered_at IS NULL AND claimed_by IS NULL`,
      [tenantId, eventId],
    );
    if (result.rowCount === 1) {
      await client.query(
        `INSERT INTO drm.audit_events (tenant_id, id, event_type, details)
         VALUES ($1, $2, 'outbox.requeued', $3)`,
        [tenantId, randomUUID(), { eventId }],
      );
    }
    return result.rowCount === 1;
  });
}

export interface OutboxDispatchResult {
  readonly delivered: number;
  readonly retried: number;
  readonly deadLettered: number;
}

export async function dispatchOutboxBatch(
  pool: Pool, tenantId: string, workerId: string,
  deliver: (event: OutboxEvent) => Promise<void>,
  limit = 25, maxAttempts = 8,
): Promise<OutboxDispatchResult> {
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 32) {
    throw new DomainError('INVALID_OUTBOX_RETRY', 'Maximum attempts must be 1–32');
  }
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new DomainError('INVALID_OUTBOX_LEASE', 'Outbox batch limit must be 1–100');
  }
  let delivered = 0;
  let retried = 0;
  let deadLettered = 0;
  for (let i = 0; i < limit; i++) {
    const event = (await claimOutboxEvents(pool, tenantId, workerId, 1, 60, maxAttempts))[0];
    if (!event) break;
    try {
      await deliver(event);
    } catch {
      const updated = event.attempts >= maxAttempts
        ? await deadLetterOutboxEvent(pool, tenantId, event.id, workerId, event.claimToken, 'DELIVERY_FAILED')
        : await releaseOutboxEvent(pool, tenantId, event.id, workerId, event.claimToken, Math.min(3600, 2 ** event.attempts), 'DELIVERY_FAILED');
      if (!updated) throw new DomainError('OUTBOX_LEASE_LOST', 'Outbox lease expired before failure was recorded');
      if (event.attempts >= maxAttempts) deadLettered++;
      else retried++;
      continue;
    }
    if (!await markOutboxDelivered(pool, tenantId, event.id, workerId, event.claimToken)) {
      throw new DomainError('OUTBOX_LEASE_LOST', 'Outbox lease expired after delivery');
    }
    delivered++;
  }
  return { delivered, retried, deadLettered };
}
