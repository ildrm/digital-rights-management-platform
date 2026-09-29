import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { cleanupTenantEphemera, withTenantTransaction } from '../src/index.ts';

test('tenant maintenance deletes only expired ephemeral rows', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test', database,
    max: 2, connectionTimeoutMillis: 3000,
  });
  const tenantId = randomUUID();
  const otherTenantId = randomUUID();
  const userId = randomUUID();
  const deviceId = randomUUID();
  try {
    for (const id of [tenantId, otherTenantId]) {
      await withTenantTransaction(pool, id, async (client) => {
        await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [id, `test-${id}`]);
        await client.query(`INSERT INTO drm.users (tenant_id, id, external_subject, status)
          VALUES ($1, $2, $3, 'active')`, [id, userId, `user-${id}`]);
        await client.query(`INSERT INTO drm.devices
          (tenant_id, id, user_id, public_key_pem, trust_level, device_class)
          VALUES ($1, $2, $3, 'test', 'software', 'desktop')`, [id, deviceId, userId]);
        for (const [offset, age] of [[0, '48 hours'], [1, '1 hour']] as const) {
          await client.query(`INSERT INTO drm.api_rate_windows
            (tenant_id, user_id, operation, window_start, request_count)
            VALUES ($1, $2, 'license-issue', clock_timestamp() - ($3::text)::interval, 1)`, [id, userId, age]);
          await client.query(`INSERT INTO drm.device_challenges
            (tenant_id, id, device_id, challenge_hash, expires_at)
            VALUES ($1, $2, $3, $4, clock_timestamp() - ($5::text)::interval)`,
          [id, randomUUID(), deviceId, Buffer.alloc(32, offset + 1), age]);
          await client.query(`INSERT INTO drm.device_enrollment_challenges
            (tenant_id, id, user_id, public_key_sha256, device_class, challenge_hash, expires_at)
            VALUES ($1, $2, $3, $4, 'desktop', $5, clock_timestamp() - ($6::text)::interval)`,
          [id, randomUUID(), userId, Buffer.alloc(32, 3), Buffer.alloc(32, offset + 3), age]);
        }
      });
    }
    assert.deepEqual(await cleanupTenantEphemera(pool, tenantId),
      { rateWindows: 1, deviceChallenges: 1, enrollmentChallenges: 1 });
    const counts = await withTenantTransaction(pool, tenantId, async (client) => {
      const rate = await client.query('SELECT count(*)::integer AS count FROM drm.api_rate_windows WHERE tenant_id = $1', [tenantId]);
      const challenges = await client.query('SELECT count(*)::integer AS count FROM drm.device_challenges WHERE tenant_id = $1', [tenantId]);
      const enrollments = await client.query('SELECT count(*)::integer AS count FROM drm.device_enrollment_challenges WHERE tenant_id = $1', [tenantId]);
      return [rate.rows[0]?.count, challenges.rows[0]?.count, enrollments.rows[0]?.count];
    });
    assert.deepEqual(counts, [1, 1, 1]);
    assert.deepEqual(await cleanupTenantEphemera(pool, tenantId),
      { rateWindows: 0, deviceChallenges: 0, enrollmentChallenges: 0 });
    const otherCount = await withTenantTransaction(pool, otherTenantId, (client) =>
      client.query('SELECT count(*)::integer AS count FROM drm.api_rate_windows WHERE tenant_id = $1', [otherTenantId]));
    assert.equal(otherCount.rows[0]?.count, 2);
  } finally {
    await pool.end();
  }
});
