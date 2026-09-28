import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DecryptCommand, DescribeKeyCommand, EncryptCommand, SignCommand,
  type KMSClient,
} from '@aws-sdk/client-kms';
import { AwsKmsKeyWrapper, AwsKmsLicenseSigner } from '../src/index.ts';

const keyArn = 'arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111';

test('AWS KMS adapter binds signatures and wrapped keys to explicit key and asset context', async () => {
  const seen: string[] = [];
  const fake = {
    async send(command: unknown) {
      if (command instanceof SignCommand) {
        assert.equal(command.input.KeyId, keyArn);
        assert.equal(command.input.MessageType, 'RAW');
        assert.equal(command.input.SigningAlgorithm, 'ED25519_SHA_512');
        seen.push('sign');
        return { KeyId: keyArn, Signature: Buffer.alloc(64, 1), SigningAlgorithm: 'ED25519_SHA_512' };
      }
      if (command instanceof EncryptCommand) {
        assert.equal(command.input.KeyId, keyArn);
        assert.deepEqual(command.input.EncryptionContext, {
          tenantId: 'tenant-a', assetId: 'asset-1', assetVersion: '1', renditionId: 'rendition-1',
        });
        seen.push('encrypt');
        return { KeyId: keyArn, CiphertextBlob: Buffer.from('wrapped') };
      }
      if (command instanceof DecryptCommand) {
        assert.equal(command.input.KeyId, keyArn);
        assert.equal(Buffer.from(command.input.CiphertextBlob ?? []).toString(), 'wrapped');
        assert.equal(command.input.EncryptionContext?.tenantId, 'tenant-a');
        seen.push('decrypt');
        return { KeyId: keyArn, Plaintext: Buffer.alloc(32, 2) };
      }
      if (command instanceof DescribeKeyCommand) {
        assert.equal(command.input.KeyId, keyArn);
        seen.push('describe');
        return { KeyMetadata: { Arn: keyArn, Enabled: true, KeyState: 'Enabled', KeyUsage: 'ENCRYPT_DECRYPT' } };
      }
      throw new Error('Unexpected AWS KMS command');
    },
  } as unknown as KMSClient;
  const signer = new AwsKmsLicenseSigner(fake, keyArn);
  assert.equal((await signer.signEd25519(Buffer.alloc(32, 9))).length, 64);
  await assert.rejects(signer.signEd25519(Buffer.from('claims')), { code: 'INVALID_SIGNING_MESSAGE' });
  const keys = new AwsKmsKeyWrapper(fake, (tenantId) => tenantId === 'tenant-a'
    ? { activeKeyArn: keyArn, permittedKeyArns: [keyArn] }
    : { activeKeyArn: '', permittedKeyArns: [] });
  const identity = { tenantId: 'tenant-a', assetId: 'asset-1', assetVersion: '1', renditionId: 'rendition-1', mimeType: 'application/pdf' };
  const wrapped = await keys.wrap(Buffer.alloc(32, 3), identity);
  assert.equal(wrapped.keyReference, keyArn);
  assert.deepEqual(await keys.unwrap(wrapped, identity), Buffer.alloc(32, 2));
  await assert.rejects(keys.unwrap({ ...wrapped, keyVersion: 'different' }, identity), { code: 'KMS_KEY_MISMATCH' });
  await keys.assertActive(keyArn, identity.tenantId, identity.assetId, 1, identity.renditionId);
  await assert.rejects(keys.unwrap(wrapped, { ...identity, tenantId: 'tenant-b' }), { code: 'INVALID_KMS_KEY' });
  assert.deepEqual(seen, ['sign', 'encrypt', 'decrypt', 'describe']);
});

test('AWS KMS adapter permits historical tenant keys during content-key rotation', async () => {
  const oldArn = 'arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222';
  const fake = {
    async send(command: unknown) {
      if (command instanceof DecryptCommand) {
        assert.equal(command.input.KeyId, oldArn);
        assert.equal(command.input.EncryptionContext?.tenantId, 'tenant-a');
        return { KeyId: oldArn, Plaintext: Buffer.alloc(32, 7) };
      }
      if (command instanceof DescribeKeyCommand) {
        assert.equal(command.input.KeyId, oldArn);
        return { KeyMetadata: { Arn: oldArn, Enabled: true, KeyState: 'Enabled', KeyUsage: 'ENCRYPT_DECRYPT' } };
      }
      throw new Error('Unexpected KMS command');
    },
  } as unknown as KMSClient;
  const keys = new AwsKmsKeyWrapper(fake, (tenantId) => tenantId === 'tenant-a'
    ? { activeKeyArn: keyArn, permittedKeyArns: [keyArn, oldArn] }
    : { activeKeyArn: keyArn, permittedKeyArns: [keyArn] });
  const identity = { tenantId: 'tenant-a', assetId: 'asset-1', assetVersion: '1', renditionId: 'r1', mimeType: 'application/pdf' };
  const oldWrapped = { provider: 'aws-kms', keyVersion: oldArn, keyReference: oldArn, ciphertext: Buffer.from('wrapped').toString('base64url') };
  assert.deepEqual(await keys.unwrap(oldWrapped, identity), Buffer.alloc(32, 7));
  await keys.assertActive(oldArn, identity.tenantId, identity.assetId, 1, identity.renditionId);
  await assert.rejects(keys.unwrap(oldWrapped, { ...identity, tenantId: 'tenant-b' }), { code: 'KMS_KEY_MISMATCH' });
});
