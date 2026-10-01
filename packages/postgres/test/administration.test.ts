import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { PostgresAdministrationService, PostgresCatalog, withTenantTransaction } from '../src/index.ts';

test('tenant administration checks stored roles, protects the last admin, and revokes grants and stored licenses', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const config = { host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'), database, max: 4 };
  const pool = new pg.Pool({ ...config, user: process.env.PG_TEST_USER ?? 'drm_app_test' });
  const runtime = new pg.Pool({ ...config, user: process.env.PG_RUNTIME_TEST_USER ?? process.env.PG_TEST_USER ?? 'drm_app_test' });
  const tenantId = randomUUID(), adminId = randomUUID(), ordinaryId = randomUUID(), assetId = randomUUID(), policyId = randomUUID(), renditionId = randomUUID();
  const service = new PostgresAdministrationService(runtime);
  try {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants(id,slug) VALUES ($1,$2)', [tenantId, `admin-${tenantId}`]);
      for (const userId of [adminId, ordinaryId]) await client.query("INSERT INTO drm.users(tenant_id,id,external_subject,status) VALUES ($1,$2,$3,'active')", [tenantId, userId, userId]);
      await client.query("INSERT INTO drm.user_roles(tenant_id,user_id,role) VALUES ($1,$2,'admin'),($1,$3,'customer')", [tenantId, adminId, ordinaryId]);
      await client.query("INSERT INTO drm.assets(tenant_id,id,owner_user_id,status) VALUES ($1,$2,$3,'published')", [tenantId, assetId, adminId]);
      await client.query('INSERT INTO drm.asset_versions(tenant_id,asset_id,version,sha256) VALUES ($1,$2,1,$3)', [tenantId, assetId, Buffer.alloc(32)]);
      await client.query("INSERT INTO drm.policies(tenant_id,id,version,asset_id,document,digest) VALUES ($1,$2,1,$3,'{}',$4)", [tenantId, policyId, assetId, Buffer.alloc(32)]);
      await client.query("INSERT INTO drm.rendition_keys(tenant_id,asset_id,asset_version,rendition_id,target,key_reference,status) VALUES ($1,$2,1,$3,'secureViewer','fixture','active')", [tenantId, assetId, renditionId]);
      await client.query(`INSERT INTO drm.asset_packages(tenant_id,asset_id,asset_version,rendition_id,object_key,package_sha256,package_bytes,mime_type,manifest_signing_key_id)
        VALUES ($1,$2,1,$3,$4,$5,10,'text/plain','fixture')`, [tenantId, assetId, renditionId, `admin/${assetId}`, Buffer.alloc(32)]);
    });
    await assert.rejects(service.provisionUser(tenantId, ordinaryId, randomUUID(), 'new-subject', ['customer']), { code: 'ACCESS_DENIED' });
    const accountKey = randomUUID();
    const account = await service.provisionUser(tenantId, adminId, accountKey, 'new-subject', ['customer']);
    assert.deepEqual(await service.provisionUser(tenantId, adminId, accountKey, 'new-subject', ['customer']), account);
    await assert.rejects(service.provisionUser(tenantId, adminId, accountKey, 'different', ['customer']), { code: 'IDEMPOTENCY_CONFLICT' });
    await assert.rejects(service.provisionUser(tenantId, adminId, randomUUID(), 'new-admin', ['admin']), { code: 'INVALID_REQUEST' });
    await assert.rejects(service.setUserStatus(tenantId, adminId, adminId, 'suspended'), { code: 'LAST_ADMIN' });
    const input = { tenantId, actorId: adminId, idempotencyKey: randomUUID(), userId: account.userId,
      assetId, assetVersion: 1, policyId, policyVersion: 1, source: 'free' as const, validUntil: null };
    await assert.rejects(service.grant({ ...input, actorId: ordinaryId }), { code: 'ACCESS_DENIED' });
    const grant = await service.grant(input);
    assert.deepEqual(await service.grant(input), grant);
    await assert.rejects(service.grant({ ...input, userId: ordinaryId }), { code: 'IDEMPOTENCY_CONFLICT' });
    assert.equal((await new PostgresCatalog(runtime).library(tenantId, account.userId)).items.length, 1);
    const deviceId = randomUUID(), licenseId = randomUUID();
    const device = generateKeyPairSync('ed25519');
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query(`INSERT INTO drm.devices(tenant_id,id,user_id,public_key_pem,trust_level,device_class)
        VALUES ($1,$2,$3,$4,'software','desktop')`, [tenantId, deviceId, account.userId, device.publicKey.export({ type: 'spki', format: 'pem' }).toString()]);
      await client.query(`INSERT INTO drm.licenses(tenant_id,id,entitlement_id,device_id,policy_id,policy_version,issued_at,expires_at,claims_sha256,rendition_id)
        VALUES ($1,$2,$3,$4,$5,1,clock_timestamp(),clock_timestamp() + interval '1 hour',$6,$7)`, [tenantId, licenseId, grant.entitlementId, deviceId, policyId, Buffer.alloc(32), renditionId]);
      await client.query('INSERT INTO drm.device_activations(tenant_id,entitlement_id,device_id) VALUES ($1,$2,$3)', [tenantId, grant.entitlementId, deviceId]);
    });
    await service.revokeGrant(tenantId, adminId, grant.entitlementId);
    await service.revokeGrant(tenantId, adminId, grant.entitlementId);
    assert.equal((await new PostgresCatalog(runtime).library(tenantId, account.userId)).items.length, 0);
    await withTenantTransaction(pool, tenantId, async (client) => {
      assert.ok((await client.query('SELECT revoked_at FROM drm.licenses WHERE tenant_id = $1 AND id = $2', [tenantId, licenseId])).rows[0].revoked_at);
      assert.ok((await client.query('SELECT released_at FROM drm.device_activations WHERE tenant_id = $1 AND entitlement_id = $2', [tenantId, grant.entitlementId])).rows[0].released_at);
    });
    await service.setUserStatus(tenantId, adminId, account.userId, 'suspended');
    await service.setUserStatus(tenantId, adminId, account.userId, 'active');
    await service.setUserStatus(tenantId, adminId, account.userId, 'revoked');
    await assert.rejects(service.setUserStatus(tenantId, adminId, account.userId, 'active'), { code: 'ACCOUNT_REVOKED' });
    await assert.rejects(service.provisionUser(randomUUID(), adminId, randomUUID(), 'foreign', ['customer']), { code: 'ACCESS_DENIED' });
    await assert.rejects(service.grant({ ...input, idempotencyKey: randomUUID(), source: 'trial', validUntil: null }), { code: 'INVALID_REQUEST' });
  } finally { await runtime.end(); await pool.end(); }
});
