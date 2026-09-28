import assert from 'node:assert/strict';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import test from 'node:test';
import { OpenBaoKeyWrapper, OpenBaoLicenseSigner, OpenBaoTransitClient } from '../src/index.ts';

test('live OpenBao Transit signs verifiable Ed25519 bytes and wraps tenant-bound content keys',
  { skip: process.env.BAO_TEST !== '1' }, async () => {
    const token = process.env.BAO_TEST_TOKEN;
    assert.ok(token, 'BAO_TEST_TOKEN must be set for live tests');
    const client = new OpenBaoTransitClient(process.env.BAO_TEST_URL ?? 'http://127.0.0.1:18200/', token,
      fetch, true);
    const metadata = await client.readKey('license-sign');
    assert.equal(metadata.type, 'ed25519');
    const keys = metadata.keys as Record<string, { public_key: string }>;
    const rawPublicKey = Buffer.from(keys['1']?.public_key ?? '', 'base64');
    assert.equal(rawPublicKey.length, 32);
    const publicKey = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawPublicKey]),
      format: 'der', type: 'spki',
    });
    const signer = new OpenBaoLicenseSigner(client, 'license-sign', 1);
    const digest = randomBytes(32);
    assert.equal(verify(null, digest, publicKey, await signer.signEd25519(digest)), true);
    const tenantId = '11111111-1111-4111-8111-111111111111';
    const wrapper = new OpenBaoKeyWrapper(client, () => ({ activeKeyName: 'tenant-key', permittedKeyNames: ['tenant-key'] }));
    const identity = { tenantId, assetId: 'asset', assetVersion: '1', renditionId: 'rendition', mimeType: 'application/pdf' };
    const contentKey = randomBytes(32);
    const wrapped = await wrapper.wrap(contentKey, identity);
    assert.deepEqual(await wrapper.unwrap(wrapped, identity), contentKey);
    await assert.rejects(wrapper.unwrap(wrapped, { ...identity, assetId: 'different' }), { code: 'BAO_DENIED' });
  });
