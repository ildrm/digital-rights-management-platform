import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { cleanupTenantEphemera, dispatchOutboxBatch } from '@drm/postgres';
import { createSignedWebhookDelivery } from './outbox-delivery.ts';
import { armHardStop, endPoolWithin } from './runtime-deadlines.ts';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
}

async function main(): Promise<void> {
  const databaseUrl = new URL(required('DATABASE_URL'));
  if (!['postgres:', 'postgresql:'].includes(databaseUrl.protocol) || !databaseUrl.hostname || databaseUrl.search) {
    throw new Error('DATABASE_URL must be a PostgreSQL URL without connection parameters');
  }
  if (process.env.DATABASE_PASSWORD_FILE) databaseUrl.password = readFileSync(required('DATABASE_PASSWORD_FILE'), 'utf8').trim();
  const secretText = readFileSync(required('WEBHOOK_SECRET_FILE'), 'utf8').trim();
  if (!/^[A-Za-z0-9_-]{43,}$/.test(secretText)) throw new Error('WEBHOOK_SECRET_FILE must contain a base64url key');
  const secret = Buffer.from(secretText, 'base64url');
  if (secret.length < 32 || secret.toString('base64url') !== secretText) {
    throw new Error('WEBHOOK_SECRET_FILE must contain at least 32 key bytes');
  }
  const deliver = createSignedWebhookDelivery(required('WEBHOOK_ENDPOINT'), secret);
  const pool = new pg.Pool({
    connectionString: databaseUrl.toString(),
    ssl: { ca: readFileSync(required('DATABASE_CA_FILE'), 'utf8'), rejectUnauthorized: true },
    max: 4, connectionTimeoutMillis: 3000, idleTimeoutMillis: 30_000,
    query_timeout: 12_000,
  });
  pool.on('error', (error) => {
    process.stderr.write(JSON.stringify({ event: 'database.idle_client_error', errorName: error.name }) + '\n');
  });
  const workerId = `webhook-${randomUUID()}`;
  let stopping = false;
  const nextCleanup = new Map<string, number>();
  let tenantCursor = 0;
  process.once('SIGTERM', () => { stopping = true; armHardStop(); });
  process.once('SIGINT', () => { stopping = true; armHardStop(); });
  try {
    await pool.query('SELECT 1');
    process.stdout.write(JSON.stringify({ event: 'outbox.started' }) + '\n');
    while (!stopping) {
      let tenantIds: string[] = [];
      try {
        const discovered = await pool.query<{ id: string }>('SELECT id FROM drm.tenants ORDER BY id');
        tenantIds = discovered.rows.map((row) => row.id);
      } catch (error) {
        process.stderr.write(JSON.stringify({ event: 'outbox.discovery_failed', errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
      }
      if (tenantIds.length) {
        const offset = tenantCursor % tenantIds.length;
        tenantIds = [...tenantIds.slice(offset), ...tenantIds.slice(0, offset)];
        tenantCursor++;
      }
      for (let index = 0; index < tenantIds.length && !stopping; index += 4) {
        await Promise.all(tenantIds.slice(index, index + 4).map(async (tenantId) => {
        try {
          const result = await dispatchOutboxBatch(pool, tenantId, workerId, deliver, 5);
          if (result.delivered || result.retried || result.deadLettered) {
            process.stdout.write(JSON.stringify({ event: 'outbox.batch', tenantId, ...result }) + '\n');
          }
          if (Date.now() >= (nextCleanup.get(tenantId) ?? 0)) {
            const total = { rateWindows: 0, deviceChallenges: 0, enrollmentChallenges: 0 };
            let backlog = false;
            for (let batch = 0; batch < 10 && !stopping; batch++) {
              const removed = await cleanupTenantEphemera(pool, tenantId);
              total.rateWindows += removed.rateWindows;
              total.deviceChallenges += removed.deviceChallenges;
              total.enrollmentChallenges += removed.enrollmentChallenges;
              backlog = Math.max(removed.rateWindows, removed.deviceChallenges, removed.enrollmentChallenges) >= 1000;
              if (!backlog) break;
            }
            nextCleanup.set(tenantId, Date.now() + (backlog ? 1_000 : 60_000));
            process.stdout.write(JSON.stringify({ event: 'maintenance.batch', tenantId, backlog, ...total }) + '\n');
          }
        } catch (error) {
          process.stderr.write(JSON.stringify({ event: 'outbox.error', tenantId, errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
        }
        }));
      }
      if (!stopping) await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  } finally {
    await endPoolWithin(pool);
    secret.fill(0);
    process.stdout.write(JSON.stringify({ event: 'outbox.stopped' }) + '\n');
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(JSON.stringify({ event: 'outbox.start_failed', errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
  process.exitCode = 1;
});
