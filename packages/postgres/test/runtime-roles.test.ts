import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { appendOutboxEvent, dispatchOutboxBatch, withTenantTransaction } from '../src/index.ts';

test('restricted runtime roles separate publication, delivery, and migration privileges', {
  skip: process.env.PG_TEST !== '1' || !process.env.PG_RUNTIME_TEST_USER || !process.env.PG_WORKER_TEST_USER,
}, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const config = { host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
    database, max: 2, connectionTimeoutMillis: 3000 };
  const fixtures = new pg.Pool({ ...config, user: process.env.PG_TEST_USER ?? 'drm_app_test' });
  const api = new pg.Pool({ ...config, user: process.env.PG_RUNTIME_TEST_USER });
  const worker = new pg.Pool({ ...config, user: process.env.PG_WORKER_TEST_USER });
  const tenantId = randomUUID();
  try {
    await withTenantTransaction(fixtures, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `roles-${tenantId}`]);
      await appendOutboxEvent(client, tenantId, 'test.created', randomUUID(), {});
    });
    for (const sql of ['DELETE FROM drm.publication_operations', 'DELETE FROM drm.audit_events',
      "UPDATE drm.publication_operations SET document = '{}'", 'SELECT * FROM public.drm_schema_migrations',
      'DELETE FROM drm.maintenance_tenants']) {
      await assert.rejects(withTenantTransaction(api, tenantId, (client) => client.query(sql)), { code: '42501' });
    }
    assert.equal((await api.query('SELECT tenant_id FROM drm.maintenance_tenants WHERE tenant_id = $1', [tenantId])).rowCount, 1);
    assert.equal((await worker.query('SELECT tenant_id FROM drm.maintenance_tenants WHERE tenant_id = $1', [tenantId])).rowCount, 1);
    assert.equal((await api.query('SELECT id FROM drm.tenants WHERE id = $1', [tenantId])).rowCount, 0);
    await assert.rejects(withTenantTransaction(worker, tenantId, (client) => client.query('SELECT * FROM drm.licenses')), { code: '42501' });
    assert.deepEqual(await dispatchOutboxBatch(worker, tenantId, 'restricted-worker', async () => {}, 1),
      { delivered: 1, retried: 0, deadLettered: 0 });
  } finally {
    await Promise.all([fixtures.end(), api.end(), worker.end()]);
  }
});
