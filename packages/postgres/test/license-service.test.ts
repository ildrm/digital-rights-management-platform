import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import { compilePolicy, verifyLicense, type Policy } from '@drm/core';
import { issueDeviceChallenge, PostgresChallengeStore, PostgresLicenseService, withTenantTransaction } from '../src/index.ts';

const enabled = process.env.PG_TEST === '1';
const trustedNow = '2026-09-28T10:00:00.000Z';

test('license issuance commits one device-bound license and audit event', { skip: !enabled }, async () => {
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
  const tenantId = randomUUID();
  const userId = randomUUID();
  const assetId = randomUUID();
  const policyId = randomUUID();
  const entitlementId = randomUUID();
  const deviceId = randomUUID();
  const otherDeviceId = randomUUID();
  const renditionId = randomUUID();
  const deviceKeys = generateKeyPairSync('ed25519');
  const issuerKeys = generateKeyPairSync('ed25519');
  const publicKeyPem = deviceKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const policy: Policy = {
    id: policyId, version: 1, tenantId, assetId,
    profile: 'protected', permissions: ['read'], prohibitions: ['downloadOriginal'],
    duties: [], constraints: { maxDevices: 1, offlineSeconds: 300 },
    preventOriginalPossession: true,
  };
  try {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `test-${tenantId}`]);
      await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')", [tenantId, userId, `idp:${userId}`]);
      for (const id of [deviceId, otherDeviceId]) {
        await client.query("INSERT INTO drm.devices (tenant_id, id, user_id, public_key_pem, trust_level, device_class) VALUES ($1, $2, $3, $4, 'software', 'desktop')", [tenantId, id, userId, publicKeyPem]);
      }
      await client.query("INSERT INTO drm.assets (tenant_id, id, owner_user_id, status) VALUES ($1, $2, $3, 'published')", [tenantId, assetId, userId]);
      await client.query('INSERT INTO drm.asset_versions (tenant_id, asset_id, version, sha256) VALUES ($1, $2, 1, $3)', [tenantId, assetId, randomBytes(32)]);
      await client.query('INSERT INTO drm.policies (tenant_id, id, version, asset_id, document, digest) VALUES ($1, $2, 1, $3, $4, $5)', [tenantId, policyId, assetId, policy, Buffer.from(compilePolicy(policy, 'secureViewer').sourceDigest, 'hex')]);
      await client.query("INSERT INTO drm.rendition_keys (tenant_id, asset_id, asset_version, rendition_id, target, key_reference, status) VALUES ($1, $2, 1, $3, 'secureViewer', 'kms://test/key', 'active')", [tenantId, assetId, renditionId]);
      await client.query("INSERT INTO drm.entitlements (tenant_id, id, subject_user_id, asset_id, asset_version, policy_id, policy_version, source, status, valid_from) VALUES ($1, $2, $3, $4, 1, $5, 1, 'free', 'active', '2026-09-01T00:00:00Z')", [tenantId, entitlementId, userId, assetId, policyId]);
    });
    const service = new PostgresLicenseService(
      pool,
      { keyId: 'test-signer', async signEd25519(message) { return sign(null, message, issuerKeys.privateKey); } },
      { async assertActive(reference, tenant, asset, version, rendition) {
        assert.deepEqual([reference, tenant, asset, version, rendition], ['kms://test/key', tenantId, assetId, 1, renditionId]);
      } },
      'integration-test', () => trustedNow,
    );
    const challenge = await issueDeviceChallenge(pool, tenantId, userId, deviceId);
    const proof = { challenge, signature: sign(null, Buffer.from(challenge), deviceKeys.privateKey).toString('base64url') };
    const request = { tenantId, authenticatedUserId: userId, entitlementId, deviceId, renditionId, action: 'read' as const, proof, requestedSeconds: 600 };
    const license = await service.issue(request);
    assert.equal(verifyLicense(license, { keyId: 'test-signer', publicKey: issuerKeys.publicKey }, deviceId, trustedNow), true);
    assert.equal(license.claims.offlineUntil, '2026-09-28T10:05:00.000Z');
    await assert.rejects(service.issue(request), { code: 'DEVICE_PROOF_REPLAY' });
    await assert.rejects(service.issue({ ...request, tenantId: randomUUID() }), { code: 'ACCESS_DENIED' });
    const otherChallenge = await issueDeviceChallenge(pool, tenantId, userId, otherDeviceId);
    const otherProof = { challenge: otherChallenge, signature: sign(null, Buffer.from(otherChallenge), deviceKeys.privateKey).toString('base64url') };
    await assert.rejects(service.issue({ ...request, deviceId: otherDeviceId, proof: otherProof }), { code: 'ACCESS_DENIED' });
    const challengeSurvived = await withTenantTransaction(pool, tenantId, async (client) => new PostgresChallengeStore(client, tenantId).consume(tenantId, otherDeviceId, otherChallenge));
    assert.equal(challengeSurvived, true);
    const counts = await withTenantTransaction(pool, tenantId, async (client) => {
      const licenses = await client.query<{ count: number }>('SELECT count(*)::integer AS count FROM drm.licenses WHERE tenant_id = $1', [tenantId]);
      const audits = await client.query<{ count: number }>("SELECT count(*)::integer AS count FROM drm.audit_events WHERE tenant_id = $1 AND event_type = 'license.issued'", [tenantId]);
      const outbox = await client.query<{ count: number }>("SELECT count(*)::integer AS count FROM drm.outbox_events WHERE tenant_id = $1 AND event_type = 'license.issued'", [tenantId]);
      return [licenses.rows[0]?.count, audits.rows[0]?.count, outbox.rows[0]?.count];
    });
    assert.deepEqual(counts, [1, 1, 1]);
    const concurrentEntitlementId = randomUUID();
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query("INSERT INTO drm.entitlements (tenant_id, id, subject_user_id, asset_id, asset_version, policy_id, policy_version, source, status, valid_from) VALUES ($1, $2, $3, $4, 1, $5, 1, 'free', 'active', '2026-09-01T00:00:00Z')", [tenantId, concurrentEntitlementId, userId, assetId, policyId]);
    });
    const firstChallenge = await issueDeviceChallenge(pool, tenantId, userId, deviceId);
    const secondChallenge = await issueDeviceChallenge(pool, tenantId, userId, otherDeviceId);
    const concurrent = await Promise.allSettled([
      service.issue({ ...request, entitlementId: concurrentEntitlementId, proof: { challenge: firstChallenge, signature: sign(null, Buffer.from(firstChallenge), deviceKeys.privateKey).toString('base64url') } }),
      service.issue({ ...request, entitlementId: concurrentEntitlementId, deviceId: otherDeviceId, proof: { challenge: secondChallenge, signature: sign(null, Buffer.from(secondChallenge), deviceKeys.privateKey).toString('base64url') } }),
    ]);
    assert.equal(concurrent.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(concurrent.filter((result) => result.status === 'rejected').length, 1);
    const rejected = concurrent.find((result) => result.status === 'rejected');
    if (rejected?.status === 'rejected') assert.equal((rejected.reason as { code?: string }).code, 'ACCESS_DENIED');
  } finally {
    await pool.end();
  }
});
