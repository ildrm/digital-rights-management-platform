import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { issueDeviceEnrollmentChallenge, registerDevice, revokeOwnedDevice, withTenantTransaction } from '../src/index.ts';

test('device enrollment proves key possession, blocks replay, and revokes owned devices', { skip: process.env.PG_TEST !== '1' }, async () => {
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
  const userId = randomUUID();
  const keys = generateKeyPairSync('ed25519');
  const otherKeys = generateKeyPairSync('ed25519');
  const publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  try {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `test-${tenantId}`]);
      await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')", [tenantId, userId, `idp:${userId}`]);
    });
    const challenge = await issueDeviceEnrollmentChallenge(pool, tenantId, userId, publicKeyPem, 'desktop');
    const input = {
      tenantId, userId, publicKeyPem, deviceClass: 'desktop', challenge,
      signature: sign(null, Buffer.from(challenge), keys.privateKey).toString('base64url'),
    };
    await assert.rejects(registerDevice(pool, { ...input, signature: sign(null, Buffer.from(challenge), otherKeys.privateKey).toString('base64url') }), { code: 'DEVICE_PROOF_INVALID' });
    await assert.rejects(registerDevice(pool, { ...input, tenantId: randomUUID() }), { code: 'ACCESS_DENIED' });
    const id = await registerDevice(pool, input);
    await assert.rejects(registerDevice(pool, input), { code: 'DEVICE_PROOF_REPLAY' });
    const result = await withTenantTransaction(pool, tenantId, async (client) => {
      const device = await client.query<{ trust_level: string; user_id: string }>(
        'SELECT trust_level, user_id FROM drm.devices WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
      const audit = await client.query<{ count: number }>(
        "SELECT count(*)::integer AS count FROM drm.audit_events WHERE tenant_id = $1 AND event_type = 'device.registered'", [tenantId]);
      const outbox = await client.query<{ count: number }>(
        "SELECT count(*)::integer AS count FROM drm.outbox_events WHERE tenant_id = $1 AND event_type = 'device.registered'", [tenantId]);
      return { device: device.rows[0], auditCount: audit.rows[0]?.count, outboxCount: outbox.rows[0]?.count };
    });
    assert.deepEqual(result, { device: { trust_level: 'software', user_id: userId }, auditCount: 1, outboxCount: 1 });
    await revokeOwnedDevice(pool, tenantId, userId, id);
    await assert.rejects(revokeOwnedDevice(pool, tenantId, userId, id), { code: 'DEVICE_NOT_FOUND' });
    const revoked = await withTenantTransaction(pool, tenantId, async (client) => {
      const device = await client.query<{ revoked: boolean }>(
        'SELECT revoked_at IS NOT NULL AS revoked FROM drm.devices WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
      return device.rows[0]?.revoked;
    });
    assert.equal(revoked, true);
  } finally {
    await pool.end();
  }
});
