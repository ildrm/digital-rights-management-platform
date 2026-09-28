import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import test from 'node:test';
import { OpenBaoKeyWrapper, OpenBaoLicenseSigner, OpenBaoTransitClient } from '../src/index.ts';

const tenantId = '11111111-1111-4111-8111-111111111111';
const otherTenantId = '22222222-2222-4222-8222-222222222222';
const identity = { tenantId, assetId: 'asset-a', assetVersion: '1', renditionId: 'rendition-a', mimeType: 'application/pdf' };

test('OpenBao Transit signs pinned Ed25519 digests and binds wrapped keys to tenant and asset', async () => {
  const pair = generateKeyPairSync('ed25519');
  const contentKey = Buffer.alloc(32, 7);
  let encryptedContext = '';
  let encryptedAad = '';
  const paths: string[] = [];
  const fakeFetch = (async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    assert.equal(url.origin, 'https://bao.test');
    assert.equal(new Headers(init?.headers).get('X-Vault-Token'), 'test-token');
    paths.push(url.pathname);
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    const reply = (data: Record<string, unknown>, status = 200) => new Response(JSON.stringify({ data }), {
      status, headers: { 'content-type': 'application/json' },
    });
    if (url.pathname === '/v1/transit/sign/license-sign') {
      assert.equal(body.key_version, 2);
      const digest = Buffer.from(String(body.input), 'base64');
      return reply({ signature: `vault:v2:${sign(null, digest, pair.privateKey).toString('base64')}` });
    }
    if (url.pathname === '/v1/transit/keys/tenant-key') {
      return reply({ type: 'aes256-gcm96', derived: true, supports_encryption: true,
        supports_decryption: true, deletion_allowed: false });
    }
    if (url.pathname === '/v1/transit/encrypt/tenant-key') {
      assert.equal(body.plaintext, contentKey.toString('base64'));
      encryptedContext = String(body.context);
      encryptedAad = String(body.associated_data);
      return reply({ ciphertext: 'vault:v3:AA==' });
    }
    if (url.pathname === '/v1/transit/decrypt/tenant-key') {
      if (body.context !== encryptedContext || body.associated_data !== encryptedAad) return reply({}, 403);
      return reply({ plaintext: contentKey.toString('base64') });
    }
    throw new Error('Unexpected OpenBao path');
  }) as typeof fetch;
  const client = new OpenBaoTransitClient('https://bao.test/', 'test-token', fakeFetch);
  const signer = new OpenBaoLicenseSigner(client, 'license-sign', 2);
  const digest = Buffer.alloc(32, 5);
  const signature = await signer.signEd25519(digest);
  assert.equal(signer.keyId, 'openbao:transit:sign:license-sign:v2');
  assert.equal(verify(null, digest, pair.publicKey, signature), true);
  await assert.rejects(signer.signEd25519(Buffer.from('not a digest')), { code: 'INVALID_SIGNING_MESSAGE' });
  const wrapper = new OpenBaoKeyWrapper(client, (tenant) => tenant === tenantId
    ? { activeKeyName: 'tenant-key', permittedKeyNames: ['tenant-key'] }
    : { activeKeyName: 'other-key', permittedKeyNames: ['other-key'] });
  const wrapped = await wrapper.wrap(contentKey, identity);
  assert.equal(wrapped.keyReference, 'openbao:transit:encrypt:tenant-key');
  assert.equal(wrapped.keyVersion, 'v3');
  assert.equal(Buffer.from(encryptedContext, 'base64').toString(), tenantId);
  assert.match(Buffer.from(encryptedAad, 'base64').toString(), /asset-a/);
  assert.deepEqual(await wrapper.unwrap(wrapped, identity), contentKey);
  await wrapper.assertActive(wrapped.keyReference, tenantId, identity.assetId, 1, identity.renditionId);
  await assert.rejects(wrapper.unwrap(wrapped, { ...identity, tenantId: otherTenantId }), { code: 'BAO_KEY_MISMATCH' });
  await assert.rejects(wrapper.unwrap(wrapped, { ...identity, assetId: 'other-asset' }), { code: 'BAO_DENIED' });
  await assert.rejects(wrapper.unwrap({ ...wrapped, keyVersion: 'v2' }, identity), { code: 'BAO_KEY_MISMATCH' });
  assert.deepEqual(paths, ['/v1/transit/sign/license-sign', '/v1/transit/keys/tenant-key',
    '/v1/transit/encrypt/tenant-key', '/v1/transit/decrypt/tenant-key',
    '/v1/transit/keys/tenant-key', '/v1/transit/decrypt/tenant-key']);
});

test('OpenBao Transit refuses non-TLS external endpoints and mismatched signing versions', async () => {
  assert.throws(() => new OpenBaoTransitClient('http://bao.example/', 'token'), { code: 'INVALID_BAO_CONFIG' });
  const fakeFetch = (async () => new Response(JSON.stringify({ data: { signature: `vault:v9:${Buffer.alloc(64).toString('base64')}` } }), {
    headers: { 'content-type': 'application/json' },
  })) as typeof fetch;
  const signer = new OpenBaoLicenseSigner(new OpenBaoTransitClient('https://bao.test/', 'token', fakeFetch), 'signer', 1);
  await assert.rejects(signer.signEd25519(Buffer.alloc(32)), { code: 'BAO_SIGNATURE_INVALID' });
});
