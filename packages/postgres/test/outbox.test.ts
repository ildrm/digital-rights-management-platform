import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { appendOutboxEvent, claimOutboxEvents, dispatchOutboxBatch, markOutboxDelivered, releaseOutboxEvent, requeueDeadLetterOutboxEvent, withTenantTransaction } from '../src/index.ts';

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
    const claimed = results.flat()[0];
    assert.equal(claimed?.id, eventId);
    assert.equal(claimed?.attempts, 1);
    assert.match(claimed?.claimToken ?? '', /^[0-9a-f-]{36}$/);
    assert.deepEqual(await claimOutboxEvents(pool, otherTenantId, 'worker-other'), []);
    assert.equal(await markOutboxDelivered(pool, tenantId, eventId, 'worker-other', claimed!.claimToken), false);
    assert.equal(await markOutboxDelivered(pool, tenantId, eventId, owner, claimed!.claimToken), true);
    assert.deepEqual(await claimOutboxEvents(pool, tenantId, 'worker-one'), []);
    const retryId = await withTenantTransaction(pool, tenantId, (client) =>
      appendOutboxEvent(client, tenantId, 'device.revoked', randomUUID(), {}));
    const retryClaim = (await claimOutboxEvents(pool, tenantId, 'worker-one', 1))[0];
    assert.equal(retryClaim?.id, retryId);
    assert.equal(await releaseOutboxEvent(pool, tenantId, retryId, 'worker-one', retryClaim!.claimToken, 60), true);
    assert.deepEqual(await claimOutboxEvents(pool, tenantId, 'worker-two'), []);
    const staleId = await withTenantTransaction(pool, tenantId, (client) =>
      appendOutboxEvent(client, tenantId, 'device.revoked', randomUUID(), {}));
    const first = (await claimOutboxEvents(pool, tenantId, 'worker-one', 1))[0]!;
    assert.equal(first.id, staleId);
    await withTenantTransaction(pool, tenantId, (client) => client.query(
      "UPDATE drm.outbox_events SET claimed_until = clock_timestamp() - interval '1 second' WHERE tenant_id = $1 AND id = $2",
      [tenantId, staleId]));
    const second = (await claimOutboxEvents(pool, tenantId, 'worker-one', 1))[0]!;
    assert.equal(second.id, staleId);
    assert.notEqual(second.claimToken, first.claimToken);
    assert.equal(await markOutboxDelivered(pool, tenantId, staleId, 'worker-one', first.claimToken), false);
    assert.equal(await markOutboxDelivered(pool, tenantId, staleId, 'worker-one', second.claimToken), true);
    const crashId = await withTenantTransaction(pool, tenantId, (client) =>
      appendOutboxEvent(client, tenantId, 'device.revoked', randomUUID(), {}));
    for (let attempt = 0; attempt < 2; attempt++) {
      const crashClaim = (await claimOutboxEvents(pool, tenantId, 'worker-one', 1, 60, 2))[0];
      assert.equal(crashClaim?.id, crashId);
      await withTenantTransaction(pool, tenantId, (client) => client.query(
        "UPDATE drm.outbox_events SET claimed_until = clock_timestamp() - interval '1 second' WHERE tenant_id = $1 AND id = $2",
        [tenantId, crashId]));
    }
    assert.deepEqual(await claimOutboxEvents(pool, tenantId, 'worker-one', 1, 60, 2), []);
    const crashed = await withTenantTransaction(pool, tenantId, (client) => client.query<{ dead_lettered: boolean }>(
      'SELECT dead_lettered_at IS NOT NULL AS dead_lettered FROM drm.outbox_events WHERE tenant_id = $1 AND id = $2',
      [tenantId, crashId]));
    assert.equal(crashed.rows[0]?.dead_lettered, true);
  } finally {
    await pool.end();
  }
});

test('outbox dispatcher retries, dead-letters, and permits explicit recovery', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test', database,
    max: 3, connectionTimeoutMillis: 3000,
  });
  const tenantId = randomUUID();
  try {
    await withTenantTransaction(pool, tenantId, (client) =>
      client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `test-${tenantId}`]));
    const eventId = await withTenantTransaction(pool, tenantId, (client) =>
      appendOutboxEvent(client, tenantId, 'license.issued', randomUUID(), { deviceId: randomUUID() }));
    let calls = 0;
    const failure = async () => { calls++; throw new Error('temporary sink failure'); };
    assert.deepEqual(await dispatchOutboxBatch(pool, tenantId, 'worker-one', failure, 1, 2),
      { delivered: 0, retried: 1, deadLettered: 0 });
    await withTenantTransaction(pool, tenantId, (client) => client.query(
      `UPDATE drm.outbox_events SET available_at = clock_timestamp() - interval '1 second'
       WHERE tenant_id = $1 AND id = $2`, [tenantId, eventId]));
    assert.deepEqual(await dispatchOutboxBatch(pool, tenantId, 'worker-one', failure, 1, 2),
      { delivered: 0, retried: 0, deadLettered: 1 });
    assert.equal(calls, 2);
    assert.deepEqual(await claimOutboxEvents(pool, tenantId, 'worker-two'), []);
    const state = await withTenantTransaction(pool, tenantId, (client) => client.query<{
      attempts: number; last_error_code: string; dead_lettered: boolean;
    }>(`SELECT attempts, last_error_code, dead_lettered_at IS NOT NULL AS dead_lettered
        FROM drm.outbox_events WHERE tenant_id = $1 AND id = $2`, [tenantId, eventId]));
    assert.deepEqual(state.rows[0], { attempts: 2, last_error_code: 'DELIVERY_FAILED', dead_lettered: true });
    assert.equal(await requeueDeadLetterOutboxEvent(pool, randomUUID(), eventId), false);
    assert.equal(await requeueDeadLetterOutboxEvent(pool, tenantId, eventId), true);
    const audit = await withTenantTransaction(pool, tenantId, (client) => client.query<{ event_type: string }>(
      `SELECT event_type FROM drm.audit_events WHERE tenant_id = $1
       AND event_type IN ('outbox.dead_lettered', 'outbox.requeued') ORDER BY occurred_at`, [tenantId]));
    assert.deepEqual(audit.rows.map((row) => row.event_type), ['outbox.dead_lettered', 'outbox.requeued']);
    const received: string[] = [];
    assert.deepEqual(await dispatchOutboxBatch(pool, tenantId, 'worker-two', async (event) => {
      received.push(event.id);
    }, 1, 2), { delivered: 1, retried: 0, deadLettered: 0 });
    assert.deepEqual(received, [eventId]);
    assert.equal(await requeueDeadLetterOutboxEvent(pool, tenantId, eventId), false);
  } finally {
    await pool.end();
  }
});
