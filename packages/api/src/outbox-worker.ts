import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { cleanupTenantEphemera, dispatchOutboxBatch } from '@drm/postgres';
import { createSignedWebhookDelivery } from './outbox-delivery.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  const tenantIds = required('OUTBOX_TENANT_IDS').split(',').map((id) => id.trim().toLowerCase());
  if (tenantIds.length < 1 || tenantIds.length > 1000 ||
      tenantIds.some((id) => !UUID.test(id)) || new Set(tenantIds).size !== tenantIds.length) {
    throw new Error('OUTBOX_TENANT_IDS must be a distinct comma-separated UUID list');
  }
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
  });
  const workerId = `webhook-${randomUUID()}`;
  let stopping = false;
  const nextCleanup = new Map<string, number>();
  process.once('SIGTERM', () => { stopping = true; });
  process.once('SIGINT', () => { stopping = true; });
  try {
    await pool.query('SELECT 1');
    process.stdout.write(JSON.stringify({ event: 'outbox.started', tenantCount: tenantIds.length }) + '\n');
    while (!stopping) {
      for (const tenantId of tenantIds) {
        if (stopping) break;
        try {
          const result = await dispatchOutboxBatch(pool, tenantId, workerId, deliver, 5);
          if (result.delivered || result.retried || result.deadLettered) {
            process.stdout.write(JSON.stringify({ event: 'outbox.batch', tenantId, ...result }) + '\n');
          }
          if (Date.now() >= (nextCleanup.get(tenantId) ?? 0)) {
            const removed = await cleanupTenantEphemera(pool, tenantId);
            nextCleanup.set(tenantId, Date.now() + 3_600_000);
            if (removed.rateWindows || removed.deviceChallenges || removed.enrollmentChallenges) {
              process.stdout.write(JSON.stringify({ event: 'maintenance.cleaned', tenantId, ...removed }) + '\n');
            }
          }
        } catch (error) {
          process.stderr.write(JSON.stringify({ event: 'outbox.error', tenantId, errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
        }
      }
      if (!stopping) await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  } finally {
    await pool.end();
    secret.fill(0);
    process.stdout.write(JSON.stringify({ event: 'outbox.stopped' }) + '\n');
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(JSON.stringify({ event: 'outbox.start_failed', errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
  process.exitCode = 1;
});
