import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { withTenantTransaction } from '../src/index.ts';

test('database disconnect between queries is contained and the pool recovers', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({ host: process.env.PG_TEST_HOST ?? '/private/tmp',
    port: Number(process.env.PG_TEST_PORT ?? '55432'), user: process.env.PG_TEST_USER ?? 'drm_app_test',
    database, max: 2, connectionTimeoutMillis: 3000 });
  try {
    await assert.rejects(withTenantTransaction(pool, randomUUID(), async (client) => {
      const pid = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
      const ended = new Promise<void>((resolve) => client.once('end', resolve));
      await pool.query('SELECT pg_terminate_backend($1)', [pid]);
      await ended;
      return 'never committed';
    }), { code: 'DATABASE_UNAVAILABLE' });
    assert.equal(await withTenantTransaction(pool, randomUUID(), async (client) =>
      (await client.query<{ ok: number }>('SELECT 1 AS ok')).rows[0]!.ok), 1);
  } finally {
    await pool.end();
  }
});
