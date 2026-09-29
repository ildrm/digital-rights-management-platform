import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { SecurePackage } from '@drm/core';
import { S3CompatiblePackageStore } from '../src/index.ts';

const tenantId = '11111111-1111-4111-8111-111111111111';
const assetId = '22222222-2222-4222-8222-222222222222';
const renditionId = '33333333-3333-4333-8333-333333333333';
const key = `tenants/${tenantId}/assets/${assetId}/versions/1/renditions/${renditionId}.drmpkg`;
const kmsArn = 'arn:aws:kms:us-east-1:123456789012:key/44444444-4444-4444-8444-444444444444';

test('S3 package writes use checksum, conditional creation, KMS encryption and no ACL', async () => {
  const commands: string[] = [];
  const fake = { async send(command: unknown) {
    if (command instanceof PutObjectCommand) {
      assert.equal(command.input.Bucket, 'drm-private-packages');
      assert.equal(command.input.Key, key);
      assert.equal(command.input.IfNoneMatch, '*');
      assert.equal(command.input.ServerSideEncryption, 'aws:kms');
      assert.equal(command.input.SSEKMSKeyId, kmsArn);
      assert.equal(command.input.ACL, undefined);
      const body = command.input.Body;
      assert.ok(Buffer.isBuffer(body));
      assert.equal(command.input.ChecksumSHA256, createHash('sha256').update(body).digest('base64'));
      commands.push('put');
      return {};
    }
    if (command instanceof DeleteObjectCommand) {
      assert.equal(command.input.Key, key);
      commands.push('delete');
      return {};
    }
    throw new Error('Unexpected S3 command');
  } } as unknown as S3Client;
  const store = new S3CompatiblePackageStore(fake, 'drm-private-packages', kmsArn);
  const pkg = { manifest: { identity: { tenantId, assetId, renditionId, assetVersion: '1' } } } as unknown as SecurePackage;
  const receipt = await store.put(key, pkg);
  assert.match(receipt.sha256, /^[a-f0-9]{64}$/);
  assert.ok(receipt.bytes > 0);
  await store.delete(key);
  assert.deepEqual(commands, ['put', 'delete']);
  await assert.rejects(store.put(key.replace(tenantId, assetId), pkg), { code: 'INVALID_STORAGE_KEY' });
});

test('S3 package reads reject altered and oversized ciphertext', async () => {
  const original = Buffer.from('{"encrypted":true}');
  const digest = createHash('sha256').update(original).digest('hex');
  let body = original;
  const fake = { async send(command: unknown) {
    assert.ok(command instanceof GetObjectCommand);
    assert.equal(command.input.Key, key);
    return { ContentLength: original.length, Body: Readable.from([body]) };
  } } as unknown as S3Client;
  const store = new S3CompatiblePackageStore(fake, 'drm-private-packages');
  assert.deepEqual(await store.get(key, digest, original.length), original);
  body = Buffer.from('{"encrypted":fals}');
  await assert.rejects(store.get(key, digest, original.length), { code: 'INVALID_STORAGE_CONTENT' });
  body = Buffer.concat([original, Buffer.from('extra')]);
  await assert.rejects(store.get(key, digest, original.length), { code: 'INVALID_STORAGE_CONTENT' });
});

test('S3-compatible self-hosted object storage accepts client-encrypted packages without AWS KMS', async () => {
  const fake = { async send(command: unknown) {
    assert.ok(command instanceof PutObjectCommand);
    assert.equal(command.input.ServerSideEncryption, undefined);
    assert.equal(command.input.SSEKMSKeyId, undefined);
    assert.equal(command.input.IfNoneMatch, '*');
    return {};
  } } as unknown as S3Client;
  const store = new S3CompatiblePackageStore(fake, 'private-packages');
  const pkg = { manifest: { identity: { tenantId, assetId, renditionId, assetVersion: '1' } } } as unknown as SecurePackage;
  assert.match((await store.put(key, pkg)).sha256, /^[a-f0-9]{64}$/);
});
