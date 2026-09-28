import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { withTenantTransaction } from '@drm/postgres';
import { consumeUserRateLimit } from '../src/index.ts';

test('PostgreSQL rate limits are atomic and tenant scoped', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp',
    port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test',
    database,
    max: 4,
    connectionTimeoutMillis: 3000,
  });
  const firstTenant = randomUUID();
  const secondTenant = randomUUID();
  const firstUser = randomUUID();
  const secondUser = randomUUID();
  try {
    for (const [tenantId, userId] of [[firstTenant, firstUser], [secondTenant, secondUser]]) {
      await withTenantTransaction(pool, tenantId!, async (client) => {
        await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `test-${tenantId}`]);
        await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')", [tenantId, userId, `idp:${userId}`]);
      });
    }
    const results = await Promise.allSettled([
      consumeUserRateLimit(pool, firstTenant, firstUser, 'license-issue', 1),
      consumeUserRateLimit(pool, firstTenant, firstUser, 'license-issue', 1),
    ]);
    assert.equal(results.filter((x) => x.status === 'fulfilled').length, 1);
    assert.equal(results.filter((x) => x.status === 'rejected').length, 1);
    const denied = results.find((x) => x.status === 'rejected');
    if (denied?.status === 'rejected') assert.equal((denied.reason as { code?: string }).code, 'RATE_LIMITED');
    await consumeUserRateLimit(pool, firstTenant, firstUser, 'device-challenge', 1);
    await consumeUserRateLimit(pool, firstTenant, firstUser, 'asset-publish', 1);
    await assert.rejects(consumeUserRateLimit(pool, firstTenant, firstUser, 'asset-publish', 1), { code: 'RATE_LIMITED' });
    await consumeUserRateLimit(pool, secondTenant, secondUser, 'license-issue', 1);
    const visibleToFirst = await withTenantTransaction(pool, firstTenant, async (client) =>
      client.query<{ count: number }>('SELECT count(*)::integer AS count FROM drm.api_rate_windows'));
    const visibleToSecond = await withTenantTransaction(pool, secondTenant, async (client) =>
      client.query<{ count: number }>('SELECT count(*)::integer AS count FROM drm.api_rate_windows'));
    assert.equal(visibleToFirst.rows[0]?.count, 3);
    assert.equal(visibleToSecond.rows[0]?.count, 1);
    await assert.rejects(consumeUserRateLimit(pool, firstTenant, secondUser, 'license-issue', 1), { code: '23503' });
  } finally {
    await pool.end();
  }
});
