import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import { LocalAccessTokenVerifier } from '../src/auth.ts';
import { LocalKeyWrapper, LocalLicenseSigner } from '../src/local-keys.ts';

const tenantId = '11111111-1111-4111-8111-111111111111';
const identity = { tenantId, assetId: 'asset', assetVersion: '1', renditionId: 'original', mimeType: 'text/plain' };

test('local signing and tenant-bound key wrapping reject wrong identity and reference', async () => {
  const signing = generateKeyPairSync('ed25519');
  const signer = new LocalLicenseSigner(signing.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'v1');
  assert.equal((await signer.signEd25519(randomBytes(32))).length, 64);
  const wrapper = new LocalKeyWrapper(randomBytes(32), 'v1');
  const contentKey = randomBytes(32);
  const wrapped = await wrapper.wrap(contentKey, identity);
  assert.deepEqual(await wrapper.unwrap(wrapped, identity), contentKey);
  await assert.rejects(wrapper.unwrap(wrapped, { ...identity, assetId: 'other' }), /authentication failed/);
  await assert.rejects(wrapper.unwrap({ ...wrapped, keyReference: 'local:wrap:v2' }, identity), /not accepted/);
  await assert.rejects(wrapper.assertActive('local:wrap:v2', tenantId, 'asset', 1, 'original'), /not active/);
});

test('local access tokens require issuer, audience, tenant, scope and short lifetime', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const verifier = new LocalAccessTokenVerifier(publicKey.export({ type: 'spki', format: 'pem' }).toString(), 'drm-local', 'drm-api', 'drm:license');
  const token = await new SignJWT({ tenant_id: tenantId, scope: 'drm:license' })
    .setProtectedHeader({ alg: 'EdDSA' }).setIssuer('drm-local').setAudience('drm-api')
    .setSubject('operator').setIssuedAt().setExpirationTime('5m').sign(privateKey);
  assert.deepEqual(await verifier.verify(`Bearer ${token}`), { tenantId, externalSubject: 'operator' });
  const wrongScope = await new SignJWT({ tenant_id: tenantId, scope: 'drm:publish' })
    .setProtectedHeader({ alg: 'EdDSA' }).setIssuer('drm-local').setAudience('drm-api')
    .setSubject('operator').setIssuedAt().setExpirationTime('5m').sign(privateKey);
  await assert.rejects(verifier.verify(`Bearer ${wrongScope}`), /Valid bearer access token/);
});
