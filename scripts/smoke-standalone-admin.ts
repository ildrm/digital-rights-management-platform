import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { operatorToken } from './lib/operator-token.ts';

const [tenantId, subject] = process.argv.slice(2);
if (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId) || !subject) throw new Error('Usage: smoke-standalone-admin.ts <tenant-uuid> <admin-subject>');
const api = process.env.SMOKE_API_URL ?? 'http://127.0.0.1:8080';
const adminToken = operatorToken(tenantId, subject, 'drm:license drm:publish drm:admin');
async function call(path: string, method: string, body: unknown, accessToken = adminToken, key?: string): Promise<Response> {
  return fetch(`${api}${path}`, { method, headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json',
    ...(key ? { 'Idempotency-Key': key } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
}
async function created<T>(response: Response): Promise<T> {
  const data = await response.json(); assert.equal(response.status, 201, JSON.stringify(data)); return data as T;
}
const content = Buffer.from('standalone administration and recovery canary');
const published = await created<{ asset: { assetId: string; policyId: string; renditionId: string; version: number } }>(await call('/v1/assets', 'POST', {
  contentBase64: content.toString('base64'), mimeType: 'text/plain',
  policy: { profile: 'protected', permissions: ['read'], prohibitions: ['downloadOriginal'], duties: [],
    constraints: { onlineOnly: true, maxDevices: 2 }, preventOriginalPossession: true },
}, adminToken, randomUUID()));
const customerSubject = `recovery-canary-${randomUUID()}`, userKey = randomUUID();
const accountBody = { subject: customerSubject, roles: ['customer'] };
const account = await created<{ userId: string }>(await call('/v1/admin/users', 'POST', accountBody, adminToken, userKey));
assert.deepEqual(await created(await call('/v1/admin/users', 'POST', accountBody, adminToken, userKey)), account);
const asset = published.asset, grantKey = randomUUID();
const grantBody = { userId: account.userId, assetId: asset.assetId, assetVersion: asset.version,
  policyId: asset.policyId, policyVersion: 1, source: 'free', validUntil: null };
const grant = await created<{ entitlementId: string }>(await call('/v1/admin/entitlements', 'POST', grantBody, adminToken, grantKey));
assert.deepEqual(await created(await call('/v1/admin/entitlements', 'POST', grantBody, adminToken, grantKey)), grant);
const offer = await created<{ offerId: string }>(await call('/v1/offers', 'POST', { assetId: asset.assetId, assetVersion: 1,
  policyId: asset.policyId, policyVersion: 1, label: 'Recovery canary', amountMinor: 1000, currency: 'usd' }, adminToken, randomUUID()));
const customerToken = operatorToken(tenantId, customerSubject, 'drm:license drm:admin');
const library = await call('/v1/library', 'GET', undefined, customerToken);
assert.equal(library.status, 200);
assert.ok((await library.json() as { items: { entitlementId: string }[] }).items.some((item) => item.entitlementId === grant.entitlementId));
assert.equal((await call('/v1/admin/users', 'POST', { subject: 'unauthorized', roles: ['customer'] }, customerToken, randomUUID())).status, 403);
assert.equal((await call('/v1/orders', 'POST', { offerId: offer.offerId }, customerToken, randomUUID())).status, 503, 'Unconfigured gateway must fail closed');
assert.equal((await call(`/v1/admin/users/${account.userId}/status`, 'POST', { status: 'suspended' })).status, 200);
assert.equal((await call('/v1/library', 'GET', undefined, customerToken)).status, 403);
assert.equal((await call(`/v1/admin/users/${account.userId}/status`, 'POST', { status: 'active' })).status, 200);
const report = { status: 'passed', recordedAt: new Date().toISOString(), tenantId, customerSubject,
  userId: account.userId, entitlementId: grant.entitlementId, ...asset, offerId: offer.offerId,
  contentSha256: createHash('sha256').update(content).digest('hex') };
if (process.env.SMOKE_REPORT_FILE) await writeFile(process.env.SMOKE_REPORT_FILE, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
process.stdout.write(JSON.stringify(report) + '\n');
