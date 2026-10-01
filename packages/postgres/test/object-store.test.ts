import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import type { SecurePackage } from '@drm/core';
import { PostgresPackageStore, withTenantTransaction } from '../src/index.ts';

test('PostgreSQL package store conditionally writes, verifies and deletes encrypted bytes',
  { skip: process.env.PG_TEST !== '1' }, async () => {
    const database = process.env.PG_TEST_DATABASE;
    assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
    const ownerPool = new pg.Pool({ host: process.env.PG_TEST_HOST ?? '/private/tmp',
      port: Number(process.env.PG_TEST_PORT ?? '55432'), user: process.env.PG_TEST_USER ?? 'drm_app_test', database });
    const runtimePool = process.env.PG_RUNTIME_TEST_USER ? new pg.Pool({
      host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
      user: process.env.PG_RUNTIME_TEST_USER, database,
    }) : ownerPool;
    const tenantId = randomUUID();
    const assetId = randomUUID();
    const renditionId = randomUUID();
    const key = `tenants/${tenantId}/assets/${assetId}/versions/1/renditions/${renditionId}.drmpkg`;
    const pkg = { manifest: { identity: { tenantId, assetId, renditionId, assetVersion: '1' } },
      ciphertext: 'encrypted bytes only' } as unknown as SecurePackage;
    const store = new PostgresPackageStore(runtimePool);
    try {
      await withTenantTransaction(ownerPool, tenantId, async (client) => {
        await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `store-${tenantId}`]);
      });
      const receipt = await store.put(key, pkg);
      const bytes = Buffer.from(JSON.stringify(pkg));
      assert.deepEqual(receipt, { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length });
      assert.deepEqual(await store.get(key, receipt.sha256, receipt.bytes), bytes);
      await assert.rejects(store.put(key, pkg), { code: 'STORAGE_CONFLICT' });
      await assert.rejects(store.get(key, '0'.repeat(64), receipt.bytes), { code: 'INVALID_STORAGE_CONTENT' });
      await assert.rejects(store.put(key, { ...pkg, manifest: { identity: { tenantId: randomUUID(), assetId, renditionId, assetVersion: '1' } } } as SecurePackage),
        { code: 'INVALID_STORAGE_KEY' });
      await store.delete(key);
      await assert.rejects(store.get(key, receipt.sha256, receipt.bytes), { code: 'STORAGE_UNAVAILABLE' });
    } finally {
      if (runtimePool !== ownerPool) await runtimePool.end();
      await ownerPool.end();
    }
  });
