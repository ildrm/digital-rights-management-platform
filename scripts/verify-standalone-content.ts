import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { openLicensedChunk, type SecurePackage, type SignedLicense } from '@drm/core';
import { LocalKeyWrapper, LocalLicenseSigner } from '../packages/api/src/local-keys.ts';
import { operatorToken } from './lib/operator-token.ts';

const [reportFile, secretDirectory, api] = process.argv.slice(2);
if (!reportFile || !secretDirectory || !api || !/^http:\/\/127\.0\.0\.1:\d+$/.test(api)) {
  throw new Error('Usage: verify-standalone-content.ts <smoke-admin-report> <recovered-secret-directory> <loopback-api-origin>');
}
const report = JSON.parse(await readFile(reportFile, 'utf8')) as { tenantId: string; customerSubject: string; entitlementId: string;
  assetId: string; renditionId: string; contentSha256: string };
const token = operatorToken(report.tenantId, report.customerSubject, 'drm:license');
const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${api}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
  const data = await response.json(); assert.equal(response.status, 201, JSON.stringify(data)); return data as T;
}
const library = await fetch(`${api}/v1/library`, { headers });
assert.equal(library.status, 200);
assert.ok((await library.json() as { items: { entitlementId: string }[] }).items.some((item) => item.entitlementId === report.entitlementId));
const keys = generateKeyPairSync('ed25519');
const deviceKey = { publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(), deviceClass: 'desktop' };
const enrollment = await post<{ challenge: string }>('/v1/device-enrollment-challenges', deviceKey);
const signature = (challenge: string) => sign(null, Buffer.from(challenge), keys.privateKey).toString('base64url');
const device = await post<{ deviceId: string }>('/v1/devices', { ...deviceKey,
  proof: { challenge: enrollment.challenge, signature: signature(enrollment.challenge) } });
try {
  const challenge = await post<{ challenge: string }>('/v1/device-challenges', { deviceId: device.deviceId });
  const { license } = await post<{ license: SignedLicense }>('/v1/licenses', { entitlementId: report.entitlementId,
    deviceId: device.deviceId, renditionId: report.renditionId, action: 'read', requestedSeconds: 60,
    proof: { challenge: challenge.challenge, signature: signature(challenge.challenge) } });
  const fetched = await fetch(`${api}/v1/assets/${report.assetId}/renditions/${report.renditionId}/package`,
    { headers: { ...headers, 'X-Drm-License-Id': license.claims.licenseId } });
  assert.equal(fetched.status, 200);
  const pkg = await fetched.json() as SecurePackage;
  const wrappingKey = Buffer.from((await readFile(join(secretDirectory, 'keys/wrapping-key'), 'utf8')).trim(), 'base64url');
  const wrapper = new LocalKeyWrapper(wrappingKey, 'v1'); wrappingKey.fill(0);
  const signer = new LocalLicenseSigner(await readFile(join(secretDirectory, 'keys/license-signing.pem'), 'utf8'), 'v1');
  const trusted = { keyId: signer.keyId, publicKey: createPublicKey(await readFile(join(secretDirectory, 'keys/license-public.pem'), 'utf8')) };
  const hash = createHash('sha256');
  for (let index = 0; index < pkg.ciphertextChunks.length; index++) {
    const plaintext = await openLicensedChunk(pkg, index, pkg.manifest.identity, wrapper, trusted, license, trusted,
      device.deviceId, new Date().toISOString(), 'read', true);
    hash.update(plaintext); plaintext.fill(0);
  }
  assert.equal(hash.digest('hex'), report.contentSha256);
  process.stdout.write(JSON.stringify({ status: 'passed', scope: 'restored-auth-library-license-package-and-keys', assetId: report.assetId }) + '\n');
} finally {
  const revoked = await fetch(`${api}/v1/devices/${device.deviceId}`, { method: 'DELETE', headers });
  assert.equal(revoked.status, 204);
}
