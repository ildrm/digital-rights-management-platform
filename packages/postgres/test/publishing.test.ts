import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import type { KeyWrapper, SecurePackage } from '@drm/core';
import { PostgresAssetPublisher, PostgresCatalog, withTenantTransaction, type ProtectedPackageStore } from '../src/index.ts';

test('publishing writes encrypted package metadata, immutable policy, audit and outbox atomically', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const pool = new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_TEST_USER ?? 'drm_app_test', database, max: 4, connectionTimeoutMillis: 3000,
  });
  const runtimePool = process.env.PG_RUNTIME_TEST_USER ? new pg.Pool({
    host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
    user: process.env.PG_RUNTIME_TEST_USER, database, max: 4, connectionTimeoutMillis: 3000,
  }) : pool;
  const tenantId = randomUUID();
  const ownerUserId = randomUUID();
  const keys = generateKeyPairSync('ed25519');
  const stored = new Map<string, SecurePackage>();
  let suspendOnPut = false;
  let putFailure: 'before' | 'after' | undefined;
  let readFailure = false;
  const store: ProtectedPackageStore = {
    async put(key, pkg) {
      if (putFailure === 'before') throw new Error('Upload failed before storage');
      if (stored.has(key)) throw new Error('Conditional write conflict');
      stored.set(key, pkg);
      if (putFailure === 'after') throw new Error('Lost upload acknowledgement');
      if (suspendOnPut) {
        await withTenantTransaction(pool, tenantId, async (client) => {
          await client.query("UPDATE drm.users SET status = 'suspended' WHERE tenant_id = $1 AND id = $2", [tenantId, ownerUserId]);
        });
      }
      const body = Buffer.from(JSON.stringify(pkg));
      return { sha256: createHash('sha256').update(body).digest('hex'), bytes: body.length };
    },
    async delete(key) { stored.delete(key); },
    async get(key, sha256, size) {
      if (readFailure) throw new Error('Storage read unavailable');
      const value = stored.get(key);
      if (!value) throw new Error('Missing object');
      const bytes = Buffer.from(JSON.stringify(value));
      assert.equal(bytes.length, size);
      assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256);
      return bytes;
    },
  };
  const wrapper: KeyWrapper = {
    async wrap(_dataKey, identity) {
      assert.equal(identity.tenantId, tenantId);
      return { provider: 'test', keyVersion: '1', keyReference: 'kms://test/content', ciphertext: Buffer.from('wrapped').toString('base64url') };
    },
    async unwrap() { throw new Error('Unexpected unwrap'); },
  };
  const publisher = new PostgresAssetPublisher(runtimePool, store, wrapper, {
    keyId: 'test-signing-key', async signEd25519(message) { return sign(null, message, keys.privateKey); },
  });
  const base = {
    idempotencyKey: randomUUID(), tenantId, ownerUserId, content: Buffer.from('sensitive-creator-content-12345'), mimeType: 'application/pdf',
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
    const catalog = new PostgresCatalog(runtimePool);
    assert.deepEqual((await catalog.owned(tenantId, ownerUserId)).items.map((item) => item.assetId), [result.assetId]);
    assert.deepEqual((await catalog.owned(tenantId, randomUUID())).items, []);
    assert.deepEqual((await catalog.owned(randomUUID(), ownerUserId)).items, []);
    const readerId = randomUUID();
    const entitlementId = randomUUID();
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')",
        [tenantId, readerId, `reader:${readerId}`]);
      await client.query(`INSERT INTO drm.entitlements
        (tenant_id, id, subject_user_id, asset_id, asset_version, policy_id, policy_version, source, status, valid_from)
        VALUES ($1, $2, $3, $4, 1, $5, 1, 'free', 'active', clock_timestamp() - interval '1 minute')`,
        [tenantId, entitlementId, readerId, result.assetId, result.policyId]);
    });
    const library = await catalog.library(tenantId, readerId);
    assert.deepEqual(library.items.map((item) => [item.entitlementId, item.assetId]), [[entitlementId, result.assetId]]);
    assert.deepEqual((await catalog.library(tenantId, ownerUserId)).items, []);
    assert.deepEqual((await catalog.library(tenantId, readerId, 20, entitlementId)).items, []);
    await assert.rejects(catalog.library(tenantId, readerId, 101), { code: 'INVALID_REQUEST' });
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query("UPDATE drm.entitlements SET status = 'revoked' WHERE tenant_id = $1 AND id = $2", [tenantId, entitlementId]);
    });
    assert.deepEqual((await catalog.library(tenantId, readerId)).items, []);
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
    await assert.rejects(publisher.publish({ ...base, idempotencyKey: randomUUID(), policy: { ...base.policy, constraints: { onlineOnly: true, territories: ['US'] } } }), { code: 'UNSUPPORTED_POLICY' });
    assert.equal(stored.size, 1);
    await assert.rejects(publisher.publish({ ...base, idempotencyKey: randomUUID(), policy: { ...base.policy, constraints: { assetVersion: '2' } } }), { code: 'UNSUPPORTED_POLICY' });
    assert.equal(stored.size, 1);
    suspendOnPut = true;
    const rejectedInput = { ...base, idempotencyKey: randomUUID() };
    await assert.rejects(publisher.publish(rejectedInput), { code: 'ACCESS_DENIED' });
    assert.equal(stored.size, 2);
    suspendOnPut = false;
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query("UPDATE drm.users SET status = 'active' WHERE tenant_id = $1 AND id = $2", [tenantId, ownerUserId]);
    });
    let remainingCommits = 3;
    const uncertainPool = {
      async connect() {
        const client = await runtimePool.connect();
        return {
          query: async (...args: Parameters<typeof client.query>) => {
            const result = await client.query(...args);
            if (args[0] === 'COMMIT' && --remainingCommits === 0) {
              throw new Error('Lost COMMIT acknowledgement');
            }
            return result;
          },
          release: (destroy?: boolean) => client.release(destroy),
          on: client.on.bind(client),
          off: client.off.bind(client),
        };
      },
    } as unknown as pg.Pool;
    const uncertainPublisher = new PostgresAssetPublisher(uncertainPool, store, wrapper, {
      keyId: 'test-signing-key', async signEd25519(message) { return sign(null, message, keys.privateKey); },
    });
    const uncertainInput = { ...base, idempotencyKey: randomUUID() };
    await assert.rejects(uncertainPublisher.publish(uncertainInput), { code: 'PUBLISH_UNCERTAIN' });
    const recovered = await publisher.publish(uncertainInput);
    assert.equal((await publisher.status(tenantId, ownerUserId, uncertainInput.idempotencyKey)).status, 'committed');
    assert.deepEqual(await publisher.publish(uncertainInput), recovered);
    const catalogKeys = await withTenantTransaction(pool, tenantId, async (client) => {
      const result = await client.query<{ object_key: string }>('SELECT object_key FROM drm.asset_packages WHERE tenant_id = $1', [tenantId]);
      return result.rows.map((row) => row.object_key);
    });
    assert.equal(catalogKeys.length, 2);
    const firstPage = await catalog.owned(tenantId, ownerUserId, 1);
    assert.equal(firstPage.items.length, 1);
    assert.ok(firstPage.nextCursor);
    const secondPage = await catalog.owned(tenantId, ownerUserId, 1, firstPage.nextCursor);
    assert.equal(secondPage.items.length, 1);
    assert.notEqual(firstPage.items[0]!.assetId, secondPage.items[0]!.assetId);
    assert.equal(secondPage.nextCursor, undefined);
    for (const key of catalogKeys) assert.ok(stored.has(key));
    await assert.rejects(publisher.publish({ ...base, content: Buffer.from('changed content') }), { code: 'IDEMPOTENCY_CONFLICT' });
    await assert.rejects(publisher.status(tenantId, randomUUID(), base.idempotencyKey), { code: 'PUBLICATION_NOT_FOUND' });
    putFailure = 'after';
    readFailure = true;
    const lostUpload = { ...base, idempotencyKey: randomUUID() };
    await assert.rejects(publisher.publish(lostUpload), { code: 'PUBLISH_UNCERTAIN' });
    assert.equal((await publisher.status(tenantId, ownerUserId, lostUpload.idempotencyKey)).status, 'pending');
    putFailure = undefined;
    readFailure = false;
    // A new publisher process recovers the persisted ciphertext through a conditional-write conflict.
    const restarted = new PostgresAssetPublisher(runtimePool, store, wrapper, {
      keyId: 'test-signing-key', async signEd25519(message) { return sign(null, message, keys.privateKey); },
    });
    const [retryOne, retryTwo] = await Promise.all([restarted.publish(lostUpload), restarted.publish(lostUpload)]);
    assert.deepEqual(retryOne, retryTwo);
    putFailure = 'before';
    const noUpload = { ...base, idempotencyKey: randomUUID() };
    await assert.rejects(publisher.publish(noUpload), { code: 'PUBLISH_UNCERTAIN' });
    putFailure = undefined;
    await restarted.reconcile(tenantId);
    assert.equal((await restarted.status(tenantId, ownerUserId, noUpload.idempotencyKey)).status, 'committed');
    // Seed an expired pending operation to test irreversible abandonment and delayed cleanup.
    putFailure = 'after';
    readFailure = true;
    const orphan = { ...base, idempotencyKey: randomUUID() };
    await assert.rejects(publisher.publish(orphan), { code: 'PUBLISH_UNCERTAIN' });
    const orphanKey = await withTenantTransaction(pool, tenantId, async (client) => {
      const row = await client.query<{ document: { asset: { objectKey: string } } }>(`WITH old AS (
        DELETE FROM drm.publication_operations WHERE tenant_id = $1 AND id = $2 RETURNING *
      ) INSERT INTO drm.publication_operations (tenant_id, id, owner_user_id, request_sha256, document, encrypted_package, created_at)
        SELECT tenant_id, id, owner_user_id, request_sha256, document, encrypted_package, clock_timestamp() - interval '25 hours'
        FROM old RETURNING document`, [tenantId, orphan.idempotencyKey]);
      return row.rows[0]!.document.asset.objectKey;
    });
    putFailure = undefined;
    readFailure = false;
    await restarted.reconcile(tenantId);
    assert.equal(stored.has(orphanKey), false);
    await assert.rejects(restarted.publish(orphan), { code: 'PUBLICATION_ABANDONED' });
    for (const key of catalogKeys) assert.ok(stored.has(key));
    await assert.rejects(withTenantTransaction(pool, tenantId, (client) => client.query(
      "UPDATE drm.publication_operations SET status = 'pending' WHERE tenant_id = $1 AND id = $2", [tenantId, orphan.idempotencyKey])), /immutable publication binding/);
  } finally {
    if (runtimePool !== pool) await runtimePool.end();
    await pool.end();
  }
});
