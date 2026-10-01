import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const [tenantId, subject] = process.argv.slice(2);
if (!tenantId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId) || !subject) {
  throw new Error('Usage: smoke-standalone.ts <existing-tenant-uuid> <active-subject>');
}
const token = execFileSync('docker', [
  'compose', '-f', 'compose.standalone.yaml', 'run', '--rm', '--no-deps', 'operator',
  'node', '--experimental-strip-types', 'scripts/issue-local-token.ts',
  '/run/secrets/auth-signing', 'drm-local', 'drm-api', tenantId, subject, 'drm:license drm:publish',
], { encoding: 'utf8' }).trim();
if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error('Operator did not issue a token');
const authorization = `Bearer ${token}`;
const body = JSON.stringify({
  contentBase64: Buffer.from('standalone Docker publish smoke content').toString('base64'),
  mimeType: 'text/plain',
  policy: { profile: 'protected', permissions: ['read'], prohibitions: ['downloadOriginal'],
    duties: [], constraints: { onlineOnly: true, maxDevices: 2 }, preventOriginalPossession: true },
});
const idempotency = randomUUID();
async function publish(): Promise<{ assetId: string }> {
  const response = await fetch('http://127.0.0.1:8080/v1/assets', {
    method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json', 'Idempotency-Key': idempotency }, body,
  });
  const result = await response.json() as { asset?: { assetId?: string }; error?: string };
  assert.equal(response.status, 201, `Publish failed: ${result.error ?? response.status}`);
  assert.ok(result.asset?.assetId);
  return { assetId: result.asset.assetId };
}
const first = await publish();
const retry = await publish();
assert.deepEqual(retry, first, 'Idempotent retry changed the asset');
const catalogResponse = await fetch('http://127.0.0.1:8080/v1/creator/assets', { headers: { Authorization: authorization } });
assert.equal(catalogResponse.status, 200);
const catalog = await catalogResponse.json() as { items?: { assetId: string }[] };
assert.ok(catalog.items?.some((item) => item.assetId === first.assetId));
process.stdout.write(JSON.stringify({ status: 'passed', assetId: first.assetId }) + '\n');
