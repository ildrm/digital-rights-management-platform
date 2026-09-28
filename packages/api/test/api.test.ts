import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import test from 'node:test';
import { createLocalJWKSet, errors as joseErrors, exportJWK, SignJWT } from 'jose';
import { DomainError, type SignedLicense } from '@drm/core';
import { createLicenseApiServer, OidcAccessTokenVerifier } from '../src/index.ts';

const tenantId = randomUUID();
const userId = randomUUID();
const deviceId = randomUUID();
const entitlementId = randomUUID();
const renditionId = randomUUID();
const issuer = 'https://identity.example.test/';
const audience = 'https://rights.example.test/api';

test('OIDC verifier rejects wrong audience, missing scope, and untrusted tenant claims', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = await exportJWK(publicKey);
  const keys = createLocalJWKSet({ keys: [{ ...publicJwk, kid: 'test-key', alg: 'RS256', use: 'sig' }] });
  const verifier = new OidcAccessTokenVerifier({ issuer, audience, jwksUrl: `${issuer}jwks`, requiredScope: 'drm:license' }, keys);
  const makeToken = (claims: Record<string, unknown>, tokenAudience = audience) =>
    new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(issuer)
      .setAudience(tokenAudience).setSubject('external-user').setIssuedAt().setExpirationTime('10m').sign(privateKey);
  const valid = await makeToken({ tenant_id: tenantId, scope: 'profile drm:license' });
  assert.deepEqual(await verifier.verify(`Bearer ${valid}`), { tenantId, externalSubject: 'external-user' });
  const publisherVerifier = new OidcAccessTokenVerifier({ issuer, audience, jwksUrl: `${issuer}jwks`, requiredScope: 'drm:publish' }, keys);
  await assert.rejects(publisherVerifier.verify(`Bearer ${valid}`), { code: 'UNAUTHENTICATED' });
  const creator = await makeToken({ tenant_id: tenantId, scope: 'drm:publish' });
  assert.deepEqual(await publisherVerifier.verify(`Bearer ${creator}`), { tenantId, externalSubject: 'external-user' });
  await assert.rejects(verifier.verify(`Bearer ${await makeToken({ tenant_id: tenantId, scope: 'drm:license' }, 'wrong-audience')}`), { code: 'UNAUTHENTICATED' });
  await assert.rejects(verifier.verify(`Bearer ${await makeToken({ tenant_id: tenantId, scope: 'profile' })}`), { code: 'UNAUTHENTICATED' });
  await assert.rejects(verifier.verify(`Bearer ${await makeToken({ tenant_id: 'another-tenant', scope: 'drm:license' })}`), { code: 'UNAUTHENTICATED' });
  await assert.rejects(verifier.verify('Bearer malformed'), { code: 'UNAUTHENTICATED' });
  const unavailable = new OidcAccessTokenVerifier({ issuer, audience, jwksUrl: `${issuer}jwks`, requiredScope: 'drm:license' },
    async () => { throw new joseErrors.JWKSTimeout(); });
  await assert.rejects(unavailable.verify(`Bearer ${valid}`), { code: 'AUTH_UNAVAILABLE' });
});

test('HTTP API binds issuance to verified identity and rejects tenant injection', { skip: process.env.API_TEST !== '1' }, async () => {
  const calls: string[] = [];
  const license = { claims: { licenseId: randomUUID() }, signature: 'test', algorithm: 'Ed25519' } as unknown as SignedLicense;
  const server = createLicenseApiServer({
    auth: {
      async verify(header) {
        if (header !== 'Bearer valid') throw new DomainError('UNAUTHENTICATED', 'Invalid token');
        calls.push('auth');
        return { tenantId, externalSubject: 'external-user' };
      },
    },
    async resolveUser(tenant, subject) {
      assert.deepEqual([tenant, subject], [tenantId, 'external-user']);
      calls.push('user');
      return userId;
    },
    async consumeRate(tenant, user, operation) {
      assert.deepEqual([tenant, user], [tenantId, userId]);
      calls.push(operation);
    },
    async issueChallenge(tenant, user, device) {
      assert.deepEqual([tenant, user, device], [tenantId, userId, deviceId]);
      calls.push('challenge');
      return 'challenge-value-1234567890';
    },
    async issueEnrollmentChallenge(tenant, user, publicKeyPem, deviceClass) {
      assert.deepEqual([tenant, user, publicKeyPem, deviceClass], [tenantId, userId, 'public-key', 'desktop']);
      calls.push('enrollment-challenge');
      return 'enrollment-challenge-1234567890';
    },
    async registerDevice(input) {
      assert.deepEqual([input.tenantId, input.userId, input.publicKeyPem, input.deviceClass], [tenantId, userId, 'public-key', 'desktop']);
      calls.push('register');
      return deviceId;
    },
    async revokeDevice(tenant, user, device) {
      assert.deepEqual([tenant, user, device], [tenantId, userId, deviceId]);
      calls.push('revoke');
    },
    licenses: {
      async issue(input) {
        assert.equal(input.tenantId, tenantId);
        assert.equal(input.authenticatedUserId, userId);
        assert.equal(input.deviceId, deviceId);
        calls.push('license');
        return license;
      },
    },
    publishAuth: {
      async verify(header) {
        if (header !== 'Bearer creator') throw new DomainError('UNAUTHENTICATED', 'Publishing scope required');
        calls.push('publish-auth');
        return { tenantId, externalSubject: 'external-user' };
      },
    },
    publisher: {
      async publish(input) {
        assert.deepEqual([input.tenantId, input.ownerUserId, input.mimeType], [tenantId, userId, 'application/pdf']);
        assert.equal(input.content.toString(), 'creator bytes');
        assert.deepEqual(input.policy.permissions, ['read']);
        calls.push('publish');
        return { assetId: randomUUID(), policyId: randomUUID(), renditionId: randomUUID(),
          version: 1, objectKey: 'encrypted-object', packageSha256: 'a'.repeat(64) };
      },
    },
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('No test listener');
    const url = `http://127.0.0.1:${address.port}`;
    const post = (path: string, body: unknown, token = 'Bearer valid') => fetch(`${url}${path}`, {
      method: 'POST', headers: { Authorization: token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const missingAuth = await post('/v1/device-challenges', { deviceId }, 'Bearer invalid');
    assert.equal(missingAuth.status, 401);
    assert.deepEqual(calls, []);
    const injected = await post('/v1/device-challenges', { deviceId, tenantId: randomUUID() });
    assert.equal(injected.status, 400);
    assert.deepEqual(calls, ['auth', 'user']);
    const challengeResponse = await post('/v1/device-challenges', { deviceId });
    assert.equal(challengeResponse.status, 201, await challengeResponse.clone().text());
    assert.equal(challengeResponse.headers.get('cache-control'), 'no-store');
    assert.equal((await challengeResponse.json()).challenge, 'challenge-value-1234567890');
    const enrollmentResponse = await post('/v1/device-enrollment-challenges', { publicKeyPem: 'public-key', deviceClass: 'desktop' });
    assert.equal(enrollmentResponse.status, 201);
    const registerResponse = await post('/v1/devices', {
      publicKeyPem: 'public-key', deviceClass: 'desktop',
      proof: { challenge: 'enrollment-challenge-1234567890', signature: 'signature' },
    });
    assert.equal(registerResponse.status, 201);
    assert.equal((await registerResponse.json()).deviceId, deviceId);
    const licenseResponse = await post('/v1/licenses', {
      entitlementId, deviceId, renditionId, action: 'read',
      proof: { challenge: 'challenge-value-1234567890', signature: 'signature' }, requestedSeconds: 60,
    });
    assert.equal(licenseResponse.status, 201);
    assert.equal((await licenseResponse.json()).license.claims.licenseId, license.claims.licenseId);
    assert.deepEqual(calls.slice(-4), ['auth', 'user', 'license-issue', 'license']);
    const revokeResponse = await fetch(`${url}/v1/devices/${deviceId}`, { method: 'DELETE', headers: { Authorization: 'Bearer valid' } });
    assert.equal(revokeResponse.status, 204);
    assert.deepEqual(calls.slice(-3), ['auth', 'user', 'revoke']);
    const publishBody = { contentBase64: Buffer.from('creator bytes').toString('base64'),
      mimeType: 'application/pdf', policy: { permissions: ['read'] } };
    assert.equal((await post('/v1/assets', publishBody)).status, 401);
    assert.equal((await post('/v1/assets', { ...publishBody, tenantId }, 'Bearer creator')).status, 400);
    const publishResponse = await post('/v1/assets', publishBody, 'Bearer creator');
    assert.equal(publishResponse.status, 201);
    assert.equal((await publishResponse.json()).asset.version, 1);
    assert.deepEqual(calls.slice(-4), ['publish-auth', 'user', 'asset-publish', 'publish']);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
