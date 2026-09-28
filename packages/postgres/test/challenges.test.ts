import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { issueDeviceChallenge, PostgresChallengeStore, withTenantTransaction } from '../src/index.ts';

const enabled = process.env.PG_TEST === '1';

test('PostgreSQL challenges are tenant-bound, owner-bound, and consumed once', { skip: !enabled }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/, 'PG_TEST_DATABASE must name a disposable drm_test_ database');
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp',
    port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test',
    database,
    max: 4,
    connectionTimeoutMillis: 3000,
  });
  const tenantId = randomUUID();
  const otherTenantId = randomUUID();
  const userId = randomUUID();
  const deviceId = randomUUID();
  try {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `test-${tenantId}`]);
      await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')", [tenantId, userId, `idp:${userId}`]);
      await client.query("INSERT INTO drm.devices (tenant_id, id, user_id, public_key_pem, trust_level, device_class) VALUES ($1, $2, $3, $4, 'software', 'desktop')", [tenantId, deviceId, userId, 'test-public-key']);
    });
    const challenge = await issueDeviceChallenge(pool, tenantId, userId, deviceId);
    assert.equal(challenge.length >= 40, true);
    await assert.rejects(issueDeviceChallenge(pool, tenantId, randomUUID(), deviceId), { code: 'DEVICE_NOT_FOUND' });
    const crossTenant = await withTenantTransaction(pool, otherTenantId, async (client) => new PostgresChallengeStore(client, otherTenantId).consume(otherTenantId, deviceId, challenge));
    assert.equal(crossTenant, false);
    const attempts = await Promise.all([
      withTenantTransaction(pool, tenantId, async (client) => new PostgresChallengeStore(client, tenantId).consume(tenantId, deviceId, challenge)),
      withTenantTransaction(pool, tenantId, async (client) => new PostgresChallengeStore(client, tenantId).consume(tenantId, deviceId, challenge)),
    ]);
    assert.deepEqual(attempts.sort(), [false, true]);
    await issueDeviceChallenge(pool, tenantId, userId, deviceId);
    await issueDeviceChallenge(pool, tenantId, userId, deviceId);
    await issueDeviceChallenge(pool, tenantId, userId, deviceId);
    await assert.rejects(issueDeviceChallenge(pool, tenantId, userId, deviceId), { code: 'CHALLENGE_LIMIT' });
    const leakedRows = await pool.query('SELECT count(*)::integer AS count FROM drm.device_challenges');
    assert.equal(leakedRows.rows[0]?.count, 0);
  } finally {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('DELETE FROM drm.device_challenges WHERE tenant_id = $1', [tenantId]);
      await client.query('DELETE FROM drm.devices WHERE tenant_id = $1', [tenantId]);
      await client.query('DELETE FROM drm.users WHERE tenant_id = $1', [tenantId]);
      await client.query('DELETE FROM drm.tenants WHERE id = $1', [tenantId]);
    });
    await pool.end();
  }
});
