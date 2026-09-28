import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import pg from 'pg';
import { openLicensedChunk, verifyLicense, type SecurePackage } from '@drm/core';
import { S3CompatiblePackageStore } from '@drm/aws-s3';
import { OpenBaoKeyWrapper, OpenBaoLicenseSigner, OpenBaoTransitClient } from '@drm/openbao';
import { issueDeviceChallenge, PostgresAssetPublisher, PostgresLicenseService, withTenantTransaction } from '../src/index.ts';

test('self-hosted OpenBao, SeaweedFS and PostgreSQL publish and license a protected asset end to end',
  { skip: process.env.SELFHOST_TEST !== '1' }, async () => {
    const database = process.env.PG_TEST_DATABASE;
    assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
    const baoToken = process.env.BAO_TEST_TOKEN;
    const s3Access = process.env.S3_TEST_ACCESS;
    const s3Secret = process.env.S3_TEST_SECRET;
    assert.ok(baoToken && s3Access && s3Secret);
    const pool = new pg.Pool({
      host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'),
      user: process.env.PG_TEST_USER ?? 'drm_app_test', database, max: 4, connectionTimeoutMillis: 3000,
    });
    const s3 = new S3Client({
      region: 'us-east-1', endpoint: process.env.S3_TEST_URL ?? 'http://127.0.0.1:18333/',
      forcePathStyle: true, credentials: { accessKeyId: s3Access, secretAccessKey: s3Secret }, maxAttempts: 1,
    });
    const store = new S3CompatiblePackageStore(s3, 'drm-private-packages');
    const bao = new OpenBaoTransitClient(process.env.BAO_TEST_URL ?? 'http://127.0.0.1:18200/', baoToken, fetch, true);
    const signer = new OpenBaoLicenseSigner(bao, 'license-sign', 1);
    const tenantId = randomUUID();
    const userId = randomUUID();
    const deviceId = randomUUID();
    const entitlementId = randomUUID();
    const deviceKeys = generateKeyPairSync('ed25519');
    const wrapper = new OpenBaoKeyWrapper(bao, () => ({ activeKeyName: 'tenant-key', permittedKeyNames: ['tenant-key'] }));
    const publisher = new PostgresAssetPublisher(pool, store, wrapper, signer);
    const content = Buffer.from('self-hosted protected document bytes');
    let objectKey: string | undefined;
    try {
      await withTenantTransaction(pool, tenantId, async (client) => {
        await client.query('INSERT INTO drm.tenants (id, slug) VALUES ($1, $2)', [tenantId, `selfhost-${tenantId}`]);
        await client.query("INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES ($1, $2, $3, 'active')",
          [tenantId, userId, `selfhost:${userId}`]);
        await client.query("INSERT INTO drm.devices (tenant_id, id, user_id, public_key_pem, trust_level, device_class) VALUES ($1, $2, $3, $4, 'software', 'desktop')",
          [tenantId, deviceId, userId, deviceKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString()]);
      });
      const published = await publisher.publish({ tenantId, ownerUserId: userId, content, mimeType: 'application/pdf',
        policy: { profile: 'protected', permissions: ['read'], prohibitions: ['downloadOriginal'],
          duties: [], constraints: { onlineOnly: true, maxDevices: 1 }, preventOriginalPossession: true } });
      objectKey = published.objectKey;
      await withTenantTransaction(pool, tenantId, async (client) => {
        await client.query(
          `INSERT INTO drm.entitlements
           (tenant_id, id, subject_user_id, asset_id, asset_version, policy_id, policy_version, source, status, valid_from)
           VALUES ($1, $2, $3, $4, 1, $5, 1, 'free', 'active', clock_timestamp() - interval '1 minute')`,
          [tenantId, entitlementId, userId, published.assetId, published.policyId],
        );
      });
      const challenge = await issueDeviceChallenge(pool, tenantId, userId, deviceId);
      const licenseService = new PostgresLicenseService(pool, signer, wrapper, 'selfhost-test', () => new Date().toISOString());
      const license = await licenseService.issue({ tenantId, authenticatedUserId: userId, entitlementId, deviceId,
        renditionId: published.renditionId, action: 'read', requestedSeconds: 300,
        proof: { challenge, signature: sign(null, Buffer.from(challenge), deviceKeys.privateKey).toString('base64url') } });
      const signingMetadata = await bao.readKey('license-sign');
      const publicKeyBytes = Buffer.from((signingMetadata.keys as Record<string, { public_key: string }>)['1']?.public_key ?? '', 'base64');
      const publicKey = createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicKeyBytes]), format: 'der', type: 'spki',
      });
      const trust = { keyId: signer.keyId, publicKey };
      assert.equal(verifyLicense(license, trust, deviceId, new Date().toISOString()), true);
      const object = await s3.send(new GetObjectCommand({ Bucket: 'drm-private-packages', Key: objectKey }));
      const bytes = Buffer.from(await object.Body!.transformToByteArray());
      assert.ok(!bytes.toString().includes(content.toString()));
      const pkg = JSON.parse(bytes.toString('utf8')) as SecurePackage;
      const opened = await openLicensedChunk(pkg, 0, {
        tenantId, assetId: published.assetId, assetVersion: '1', renditionId: published.renditionId,
        mimeType: 'application/pdf',
      }, wrapper, trust, license, trust, deviceId, new Date().toISOString(), 'read');
      assert.deepEqual(opened, content);
    } finally {
      if (objectKey) await store.delete(objectKey);
      s3.destroy();
      await pool.end();
    }
  });
