import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import { GetObjectCommand, HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { createSecurePackage } from '@drm/core';
import { S3CompatiblePackageStore } from '../src/index.ts';

test('live self-hosted S3 endpoint stores only encrypted package bytes and honors conditional put',
  { skip: process.env.S3_TEST !== '1' }, async () => {
    const accessKeyId = process.env.S3_TEST_ACCESS;
    const secretAccessKey = process.env.S3_TEST_SECRET;
    assert.ok(accessKeyId && secretAccessKey, 'S3_TEST_ACCESS and S3_TEST_SECRET are required');
    const client = new S3Client({
      region: 'us-east-1', endpoint: process.env.S3_TEST_URL ?? 'http://127.0.0.1:18333/',
      forcePathStyle: true, credentials: { accessKeyId, secretAccessKey }, maxAttempts: 1,
    });
    const store = new S3CompatiblePackageStore(client, 'drm-private-packages');
    const tenantId = randomUUID();
    const assetId = randomUUID();
    const renditionId = randomUUID();
    const key = `tenants/${tenantId}/assets/${assetId}/versions/1/renditions/${renditionId}.drmpkg`;
    const pair = generateKeyPairSync('ed25519');
    const plaintext = Buffer.from('unique-secret-content-never-in-object');
    const pkg = await createSecurePackage(plaintext, {
      tenantId, assetId, assetVersion: '1', renditionId, mimeType: 'application/pdf',
    }, {
      async wrap() { return { provider: 'test', keyVersion: '1', keyReference: 'test-key', ciphertext: 'd3JhcHBlZA' }; },
      async unwrap() { throw new Error('Unexpected unwrap'); },
    }, { keyId: 'test-signing-key', async signEd25519(message) { return sign(null, message, pair.privateKey); } });
    try {
      const receipt = await store.put(key, pkg);
      const read = await client.send(new GetObjectCommand({ Bucket: 'drm-private-packages', Key: key }));
      const bytes = Buffer.from(await read.Body!.transformToByteArray());
      assert.equal(createHash('sha256').update(bytes).digest('hex'), receipt.sha256);
      assert.ok(!bytes.toString().includes(plaintext.toString()));
      const metadata = await client.send(new HeadObjectCommand({ Bucket: 'drm-private-packages', Key: key }));
      assert.equal(metadata.Metadata?.['package-sha256'], receipt.sha256);
      await assert.rejects(store.put(key, pkg));
    } finally {
      await store.delete(key);
      client.destroy();
    }
  });
