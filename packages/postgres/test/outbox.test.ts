import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { appendOutboxEvent, claimOutboxEvents, markOutboxDelivered, releaseOutboxEvent, withTenantTransaction } from '../src/index.ts';

test('outbox claims are exclusive, tenant scoped, and acknowledged by lease owner', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp',
    port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test',
    database,
    max: 4, connectionTimeoutMillis: 3000,
  });
  const tenantId = randomUUID();
  const otherTenantId = randomUUID();
  const aggregateId = randomUUID();
  try {
    for (const id of [tenantId, otherTenantId]) {
      await withTenantTransaction(pool, id, async (client) => {
        await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [id, `test-${id}`]);
      });
    }
    const eventId = await withTenantTransaction(pool, tenantId, (client) =>
      appendOutboxEvent(client, tenantId, 'license.issued', aggregateId, { assetId: randomUUID() }));
    const results = await Promise.all([
      claimOutboxEvents(pool, tenantId, 'worker-one', 1),
      claimOutboxEvents(pool, tenantId, 'worker-two', 1),
    ]);
    assert.equal(results.flat().length, 1);
    const owner = results[0]?.length ? 'worker-one' : 'worker-two';
    assert.equal(results.flat()[0]?.id, eventId);
    assert.equal(results.flat()[0]?.attempts, 1);
    assert.deepEqual(await claimOutboxEvents(pool, otherTenantId, 'worker-other'), []);
    assert.equal(await markOutboxDelivered(pool, tenantId, eventId, 'worker-other'), false);
    assert.equal(await markOutboxDelivered(pool, tenantId, eventId, owner), true);
    assert.deepEqual(await claimOutboxEvents(pool, tenantId, 'worker-one'), []);
    const retryId = await withTenantTransaction(pool, tenantId, (client) =>
      appendOutboxEvent(client, tenantId, 'device.revoked', randomUUID(), {}));
    assert.equal((await claimOutboxEvents(pool, tenantId, 'worker-one', 1))[0]?.id, retryId);
    assert.equal(await releaseOutboxEvent(pool, tenantId, retryId, 'worker-one', 60), true);
    assert.deepEqual(await claimOutboxEvents(pool, tenantId, 'worker-two'), []);
  } finally {
    await pool.end();
  }
});
