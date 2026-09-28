import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import type { KeyWrapper, SecurePackage } from '@drm/core';
import { PostgresAssetPublisher, withTenantTransaction, type ProtectedPackageStore } from '../src/index.ts';

test('publishing writes encrypted package metadata, immutable policy, audit and outbox atomically', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test', database, max: 4, connectionTimeoutMillis: 3000,
  });
  const tenantId = randomUUID();
  const ownerUserId = randomUUID();
  const keys = generateKeyPairSync('ed25519');
  const stored = new Map<string, SecurePackage>();
  let suspendOnPut = false;
  const store: ProtectedPackageStore = {
    async put(key, pkg) {
      stored.set(key, pkg);
      if (suspendOnPut) {
        await withTenantTransaction(pool, tenantId, async (client) => {
          await client.query("UPDATE drm.users SET status = 'suspended' WHERE tenant_id = $1 AND id = $2", [tenantId, ownerUserId]);
        });
      }
      const body = Buffer.from(JSON.stringify(pkg));
      return { sha256: createHash('sha256').update(body).digest('hex'), bytes: body.length };
    },
    async delete(key) { stored.delete(key); },
  };
  const wrapper: KeyWrapper = {
    async wrap(_dataKey, identity) {
      assert.equal(identity.tenantId, tenantId);
      return { provider: 'test', keyVersion: '1', keyReference: 'kms://test/content', ciphertext: Buffer.from('wrapped').toString('base64url') };
    },
    async unwrap() { throw new Error('Unexpected unwrap'); },
  };
  const publisher = new PostgresAssetPublisher(pool, store, wrapper, {
    keyId: 'test-signing-key', async signEd25519(message) { return sign(null, message, keys.privateKey); },
  });
  const base = {
    tenantId, ownerUserId, content: Buffer.from('sensitive-creator-content-12345'), mimeType: 'application/pdf',
    policy: {
      profile: 'protected' as const, permissions: ['read'] as const, prohibitions: ['downloadOriginal'] as const,
      duties: [], constraints: { onlineOnly: true, maxDevices: 2 }, preventOriginalPossession: true,
    },
  };
  try {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `publish-${tenantId}`]);
      await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')", [tenantId, ownerUserId, `creator:${ownerUserId}`]);
    });
    const result = await publisher.publish(base);
    assert.equal(result.version, 1);
    assert.equal(stored.size, 1);
    assert.equal(stored.get(result.objectKey)?.manifest.identity.assetId, result.assetId);
    assert.ok(!JSON.stringify(stored.get(result.objectKey)).includes(base.content.toString()));
    const counts = await withTenantTransaction(pool, tenantId, async (client) => {
      const rows = [];
      rows.push(await client.query<{ count: number }>('SELECT count(*)::integer AS count FROM drm.assets WHERE tenant_id = $1', [tenantId]));
      rows.push(await client.query<{ count: number }>('SELECT count(*)::integer AS count FROM drm.asset_packages WHERE tenant_id = $1 AND object_key = $2', [tenantId, result.objectKey]));
      rows.push(await client.query<{ count: number }>("SELECT count(*)::integer AS count FROM drm.audit_events WHERE tenant_id = $1 AND event_type = 'asset.published'", [tenantId]));
      rows.push(await client.query<{ count: number }>("SELECT count(*)::integer AS count FROM drm.outbox_events WHERE tenant_id = $1 AND event_type = 'asset.published'", [tenantId]));
      return rows.map((row) => row.rows[0]?.count);
    });
    assert.deepEqual(counts, [1, 1, 1, 1]);
    await assert.rejects(withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('UPDATE drm.asset_packages SET mime_type = $1 WHERE tenant_id = $2 AND asset_id = $3',
        ['text/plain', tenantId, result.assetId]);
    }), /immutable record/);
    const otherTenantCount = await withTenantTransaction(pool, randomUUID(), async (client) => {
      const row = await client.query<{ count: number }>('SELECT count(*)::integer AS count FROM drm.asset_packages');
      return row.rows[0]?.count;
    });
    assert.equal(otherTenantCount, 0);
    await assert.rejects(publisher.publish({ ...base, policy: { ...base.policy, constraints: { onlineOnly: true, territories: ['US'] } } }), { code: 'UNSUPPORTED_POLICY' });
    assert.equal(stored.size, 1);
    suspendOnPut = true;
    await assert.rejects(publisher.publish(base), { code: 'ACCESS_DENIED' });
    assert.equal(stored.size, 1);
  } finally {
    await pool.end();
  }
});
