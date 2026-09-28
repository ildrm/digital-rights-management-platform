import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import test from 'node:test';
import {
  analyzeCompatibility, compilePolicy, createSecurePackage, evaluateAccess,
  LicenseIssuer, openLicensedChunk, verifyLicense,
  type AccessRequest, type ChallengeStore, type KeyWrapper, type PackageIdentity, type Policy,
} from '../src/index.ts';

const now = '2026-09-28T10:00:00.000Z';
const deviceKeys = generateKeyPairSync('ed25519');
const issuerKeys = generateKeyPairSync('ed25519');
const trustedIssuer = { keyId: 'test-signing-key', publicKey: issuerKeys.publicKey };
const policy: Policy = {
  id: 'policy-1', version: 1, tenantId: 'tenant-a', assetId: 'asset-1',
  profile: 'protected', permissions: ['read', 'downloadProtected'], prohibitions: ['downloadOriginal'],
  duties: [{ type: 'payment', reference: 'order-1' }],
  constraints: { maxDevices: 2, expiresAt: '2026-09-29T10:00:00.000Z', offlineSeconds: 600 },
  preventOriginalPossession: true,
};
const request: AccessRequest = {
  principal: { kind: 'user', id: 'user-1', tenantId: 'tenant-a' },
  device: { id: 'device-1', tenantId: 'tenant-a', userId: 'user-1', publicKeyPem: deviceKeys.publicKey.export({ format: 'pem', type: 'spki' }).toString(), trust: 'software', deviceClass: 'desktop' },
  entitlement: {
    id: 'ent-1', tenantId: 'tenant-a', subject: { kind: 'user', id: 'user-1', tenantId: 'tenant-a' },
    assetId: 'asset-1', assetVersion: 'v1', policyId: 'policy-1', policyVersion: 1,
    source: 'purchase', status: 'active', validFrom: '2026-09-01T00:00:00.000Z',
  },
  policy, assetVersion: 'v1', action: 'read',
  context: {
    now, territory: 'GB', online: true, roles: [], activeDeviceCount: 0,
    activeSessionCount: 0, useCount: 0, exportCount: 0, creditsUsed: 0,
    fulfilledDuties: ['payment:order-1'],
  },
};

test('policy compiler is deterministic and rejects silent weakening', () => {
  const compiled = compilePolicy(policy, 'secureViewer');
  assert.equal(compiled.allowedActions.join(','), 'downloadProtected,read');
  assert.equal(compiled.sourceDigest, compilePolicy(policy, 'secureViewer').sourceDigest);
  assert.equal(analyzeCompatibility(policy, 'widevine').compatible, false);
  assert.throws(() => compilePolicy(policy, 'widevine'), { code: 'UNSUPPORTED_POLICY' });
  const videoPolicy: Policy = { ...policy, permissions: ['play', 'stream'], constraints: {} };
  assert.equal(analyzeCompatibility(videoPolicy, 'widevine').compatible, false);
  assert.throws(() => compilePolicy(videoPolicy, 'widevine'), { code: 'UNSUPPORTED_POLICY' });
  assert.throws(() => compilePolicy({ ...policy, permissions: ['downloadOriginal'] }, 'secureViewer'), { code: 'POLICY_CONTRADICTION' });
  assert.throws(() => compilePolicy({ ...policy, constraints: { onlineOnly: true, offlineSeconds: 60 } }, 'secureViewer'), { code: 'POLICY_CONTRADICTION' });
  assert.throws(() => compilePolicy({ ...policy, constraints: { mystery: true } } as unknown as Policy, 'secureViewer'), { code: 'INVALID_POLICY' });
});

test('entitlement is tenant-bound, action-bound, time-bound, and duty-bound', () => {
  assert.equal(evaluateAccess(request).allowed, true);
  assert.equal(evaluateAccess({ ...request, device: { ...request.device, tenantId: 'tenant-b' } }).allowed, false);
  assert.equal(evaluateAccess({ ...request, action: 'downloadOriginal' }).allowed, false);
  assert.equal(evaluateAccess({ ...request, context: { ...request.context, now: '2026-09-30T00:00:00.000Z' } }).allowed, false);
  assert.equal(evaluateAccess({ ...request, context: { ...request.context, fulfilledDuties: [] } }).allowed, false);
  assert.equal(evaluateAccess({ ...request, entitlement: { ...request.entitlement, policyVersion: 2 } }).allowed, false);
  assert.equal(evaluateAccess({ ...request, context: { ...request.context, activeDeviceCount: 1 } }).allowed, true);
  assert.equal(evaluateAccess({ ...request, context: { ...request.context, activeDeviceCount: 2 } }).allowed, false);
});

test('license requires device proof and consumes each challenge once', async () => {
  const outstanding = new Set(['server-challenge-0001']);
  const challenges: ChallengeStore = {
    async consume(tenantId, deviceId, challenge) {
      if (tenantId !== 'tenant-a' || deviceId !== 'device-1' || !outstanding.has(challenge)) return false;
      outstanding.delete(challenge);
      return true;
    },
  };
  const issuer = new LicenseIssuer({ keyId: 'test-signing-key', async signEd25519(message) { return sign(null, message, issuerKeys.privateKey); } }, challenges, () => now);
  const deviceProof = { challenge: 'server-challenge-0001', signature: sign(null, Buffer.from('server-challenge-0001'), deviceKeys.privateKey).toString('base64url') };
  const input = { ...request, renditionId: 'r1', deviceProof, keyReference: 'kms:key-1', issuer: 'local-test', requestedSeconds: 900 };
  const license = await issuer.issue(input);
  assert.equal(license.claims.deviceId, 'device-1');
  assert.equal(license.claims.offlineUntil, '2026-09-28T10:10:00.000Z');
  assert.equal(verifyLicense(license, trustedIssuer, 'device-1', now), true);
  assert.equal(verifyLicense(license, { ...trustedIssuer, keyId: 'different-key' }, 'device-1', now), false);
  assert.equal(verifyLicense(license, trustedIssuer, 'another-device', now), false);
  assert.equal(verifyLicense({ ...license, claims: { ...license.claims, assetId: 'forged' } }, trustedIssuer, 'device-1', now), false);
  await assert.rejects(issuer.issue(input), { code: 'DEVICE_PROOF_REPLAY' });
  await assert.rejects(issuer.issue({ ...input, deviceProof: { ...deviceProof, signature: 'bad' } }), { code: 'DEVICE_PROOF_INVALID' });
});

test('encrypted package authenticates content, metadata, and tenant identity', async () => {
  const identity: PackageIdentity = { tenantId: 'tenant-a', assetId: 'asset-1', assetVersion: 'v1', renditionId: 'r1', mimeType: 'text/plain' };
  const root = randomBytes(32);
  const keys: KeyWrapper = {
    async wrap(dataKey, context) {
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', root, nonce);
      cipher.setAAD(Buffer.from(JSON.stringify(context)));
      const encrypted = Buffer.concat([cipher.update(dataKey), cipher.final()]);
      return { provider: 'test-only', keyVersion: '1', keyReference: 'kms:key-1', ciphertext: Buffer.concat([nonce, cipher.getAuthTag(), encrypted]).toString('base64url') };
    },
    async unwrap(wrapped, context) {
      const raw = Buffer.from(wrapped.ciphertext, 'base64url');
      const decipher = createDecipheriv('aes-256-gcm', root, raw.subarray(0, 12));
      decipher.setAAD(Buffer.from(JSON.stringify(context)));
      decipher.setAuthTag(raw.subarray(12, 28));
      return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
    },
  };
  const content = Buffer.from('private content split across authenticated chunks');
  const signer = { keyId: 'test-signing-key', async signEd25519(message: Buffer) { return sign(null, message, issuerKeys.privateKey); } };
  const pkg = await createSecurePackage(content, identity, keys, signer, 16);
  const challenge = 'package-challenge-0001';
  const license = await new LicenseIssuer(
    signer,
    { async consume() { return true; } }, () => now,
  ).issue({ ...request, renditionId: 'r1', deviceProof: { challenge, signature: sign(null, Buffer.from(challenge), deviceKeys.privateKey).toString('base64url') }, keyReference: 'kms:key-1', issuer: 'local-test', requestedSeconds: 900 });
  const open = (candidate: typeof pkg, candidateIdentity = identity, action: typeof request.action = 'read') =>
    openLicensedChunk(candidate, 0, candidateIdentity, keys, trustedIssuer, license, trustedIssuer, request.device.id, now, action);
  const opened = await Promise.all(pkg.manifest.chunks.map((chunk) => openLicensedChunk(pkg, chunk.index, identity, keys, trustedIssuer, license, trustedIssuer, request.device.id, now, 'read')));
  assert.deepEqual(Buffer.concat(opened), content);
  await assert.rejects(open(pkg, { ...identity, tenantId: 'tenant-b' }), { code: 'LICENSE_SCOPE' });
  await assert.rejects(open(pkg, identity, 'play'), { code: 'LICENSE_SCOPE' });
  await assert.rejects(open({ ...pkg, manifest: { ...pkg.manifest, wrappedKey: { ...pkg.manifest.wrappedKey, keyReference: 'other' } } }), { code: 'LICENSE_SCOPE' });
  const altered = { ...pkg, ciphertextChunks: ['AAAA', ...pkg.ciphertextChunks.slice(1)] };
  await assert.rejects(open(altered), { code: 'INVALID_CHUNK' });
  const forged = { ...pkg, manifest: { ...pkg.manifest, totalBytes: 1 } };
  await assert.rejects(open(forged), { code: 'INVALID_SIGNATURE' });
  await assert.rejects(openLicensedChunk(pkg, 0, identity, keys, { ...trustedIssuer, keyId: 'wrong-key' }, license, trustedIssuer, request.device.id, now, 'read'), { code: 'INVALID_SIGNING_KEY' });
  await assert.rejects(createSecurePackage(Buffer.alloc(17_000), identity, keys, signer, 1), { code: 'INVALID_CHUNK_SIZE' });
  root.fill(0);
});
