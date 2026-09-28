import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import test from 'node:test';
import { LicenseIssuer, type AccessRequest, type Policy } from '@drm/core';
import { AxinomPlaybackTokenIssuer } from '../src/index.ts';

const now = '2026-09-28T10:00:00.000Z';
const contentKeyId = '7459975d-b2f8-48ed-a325-56e4f34d19c7';
const signingKeys = generateKeyPairSync('ed25519');
const trustedSigningKey = { keyId: 'test-signing-key', publicKey: signingKeys.publicKey };
const deviceKeys = generateKeyPairSync('ed25519');
const communicationKey = randomBytes(32);
const policy: Policy = {
  id: 'media-policy', version: 1, tenantId: 'tenant-a', assetId: 'asset-1',
  profile: 'protected', permissions: ['play'], prohibitions: ['downloadOriginal'], duties: [],
  constraints: { onlineOnly: true }, preventOriginalPossession: true,
};
const request: AccessRequest = {
  principal: { kind: 'user', id: 'user-1', tenantId: 'tenant-a' },
  device: { id: 'device-1', tenantId: 'tenant-a', userId: 'user-1', publicKeyPem: deviceKeys.publicKey.export({ format: 'pem', type: 'spki' }).toString(), trust: 'software', deviceClass: 'browser' },
  entitlement: { id: 'ent-1', tenantId: 'tenant-a', subject: { kind: 'user', id: 'user-1', tenantId: 'tenant-a' }, assetId: 'asset-1', assetVersion: 'v1', policyId: 'media-policy', policyVersion: 1, source: 'purchase', status: 'active', validFrom: '2026-09-01T00:00:00.000Z' },
  policy, assetVersion: 'v1', action: 'play',
  context: { now, territory: 'GB', online: true, roles: [], activeDeviceCount: 0, activeSessionCount: 0, useCount: 0, exportCount: 0, creditsUsed: 0, fulfilledDuties: [] },
};

test('Axinom token is scoped to one verified key and expires in thirty seconds', async () => {
  const signer = { keyId: 'test-signing-key', async signEd25519(message: Buffer) { return sign(null, message, signingKeys.privateKey); } };
  const issuer = new LicenseIssuer(signer, { async consume() { return true; } }, () => now);
  const challenge = 'axinom-challenge-0001';
  const license = await issuer.issue({ ...request, renditionId: 'media-1', deviceProof: { challenge, signature: sign(null, Buffer.from(challenge), deviceKeys.privateKey).toString('base64url') }, keyReference: `axinom:${contentKeyId}`, issuer: 'local-test', requestedSeconds: 120 });
  const adapter = new AxinomPlaybackTokenIssuer(async (tenantId) => {
    assert.equal(tenantId, 'tenant-a');
    return { communicationKeyId: 'aa0151d7-081c-4699-a049-fc584556c9d2', communicationKeyBase64: communicationKey.toString('base64') };
  });
  const token = await adapter.issue(license, trustedSigningKey, 'device-1', now, contentKeyId);
  assert.equal(token.headerName, 'X-AxDRM-Message');
  assert.equal(token.expiresAt, '2026-09-28T10:00:30.000Z');
  const [header, payload, signature] = token.token.split('.');
  assert.equal(createHmac('sha256', communicationKey).update(`${header}.${payload}`).digest('base64url'), signature);
  const envelope = JSON.parse(Buffer.from(payload!, 'base64url').toString());
  assert.equal(envelope.message.content_keys_source.inline[0].id, contentKeyId);
  assert.equal(envelope.message.license.allow_persistence, false);
  assert.equal(envelope.message.license.duration, 30);
  await assert.rejects(adapter.issue(license, trustedSigningKey, 'device-2', now, contentKeyId), { code: 'LICENSE_INVALID' });
  await assert.rejects(adapter.issue(license, { ...trustedSigningKey, keyId: 'wrong-key' }, 'device-1', now, contentKeyId), { code: 'LICENSE_INVALID' });
  await assert.rejects(adapter.issue(license, trustedSigningKey, 'device-1', now, '11111111-1111-4111-8111-111111111111'), { code: 'AXINOM_KEY_SCOPE' });
  await assert.rejects(adapter.issue({ ...license, claims: { ...license.claims, rights: ['downloadOriginal'] } }, trustedSigningKey, 'device-1', now, contentKeyId), { code: 'LICENSE_INVALID' });
  await assert.rejects(adapter.issue(license, trustedSigningKey, 'device-1', '2026-09-28T10:03:00.000Z', contentKeyId), { code: 'LICENSE_INVALID' });
  communicationKey.fill(0);
});
