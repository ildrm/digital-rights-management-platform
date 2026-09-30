import {
  DecryptCommand, DescribeKeyCommand, EncryptCommand, SignCommand,
  type KMSClient,
} from '@aws-sdk/client-kms';
import { DomainError, type KeyWrapper, type LicenseSigner, type PackageIdentity, type WrappedKey } from '@drm/core';

export interface TenantKeyRing {
  readonly activeKeyArn: string;
  readonly permittedKeyArns: readonly string[];
}

export type TenantKeyResolver = (tenantId: string) => TenantKeyRing;

function context(identity: PackageIdentity): Record<string, string> {
  return {
    tenantId: identity.tenantId,
    assetId: identity.assetId,
    assetVersion: identity.assetVersion,
    renditionId: identity.renditionId,
  };
}

function requireArn(value: string): void {
  if (!/^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/i.test(value)) {
    throw new DomainError('INVALID_KMS_KEY', 'A concrete AWS KMS key ARN is required');
  }
}

export class AwsKmsLicenseSigner implements LicenseSigner {
  readonly keyId: string;
  private readonly client: KMSClient;

  constructor(client: KMSClient, signingKeyArn: string) {
    requireArn(signingKeyArn);
    this.client = client;
    this.keyId = signingKeyArn;
  }

  async signEd25519(message: Buffer): Promise<Buffer> {
    if (message.length !== 32) throw new DomainError('INVALID_SIGNING_MESSAGE', 'Signer accepts only a domain-separated SHA-256 digest');
    let response;
    try {
      response = await this.client.send(new SignCommand({
        KeyId: this.keyId,
        Message: message,
        MessageType: 'RAW',
        SigningAlgorithm: 'ED25519_SHA_512',
      }), { abortSignal: AbortSignal.timeout(3000) });
    } catch {
      throw new DomainError('KMS_UNAVAILABLE', 'Signing service is unavailable');
    }
    if (!response.Signature || response.Signature.length !== 64 || response.SigningAlgorithm !== 'ED25519_SHA_512' || response.KeyId !== this.keyId) {
      throw new DomainError('KMS_SIGNATURE_INVALID', 'KMS did not return an Ed25519 signature');
    }
    return Buffer.from(response.Signature);
  }
}

export class AwsKmsKeyWrapper implements KeyWrapper {
  private readonly client: KMSClient;
  private readonly resolveKey: TenantKeyResolver;

  constructor(client: KMSClient, resolveKey: TenantKeyResolver) {
    this.client = client;
    this.resolveKey = resolveKey;
  }

  private ring(tenantId: string): TenantKeyRing {
    const ring = this.resolveKey(tenantId);
    if (!ring || !Array.isArray(ring.permittedKeyArns) || !ring.permittedKeyArns.includes(ring.activeKeyArn)) {
      throw new DomainError('INVALID_KMS_KEY', 'Tenant KMS key ring is unavailable or inconsistent');
    }
    requireArn(ring.activeKeyArn);
    for (const arn of ring.permittedKeyArns) requireArn(arn);
    return ring;
  }

  async wrap(dataKey: Buffer, identity: PackageIdentity): Promise<WrappedKey> {
    if (dataKey.length !== 32) throw new DomainError('INVALID_KEY', 'Content key must be 256 bits');
    const keyArn = this.ring(identity.tenantId).activeKeyArn;
    requireArn(keyArn);
    let response;
    try {
      response = await this.client.send(new EncryptCommand({
        KeyId: keyArn,
        Plaintext: dataKey,
        EncryptionContext: context(identity),
      }), { abortSignal: AbortSignal.timeout(3000) });
    } catch {
      throw new DomainError('KMS_UNAVAILABLE', 'Content-key service is unavailable');
    }
    if (!response.CiphertextBlob?.length || response.KeyId !== keyArn) throw new DomainError('KMS_ENCRYPT_FAILED', 'KMS returned no wrapped key or a different key');
    return {
      provider: 'aws-kms', keyVersion: response.KeyId ?? keyArn,
      keyReference: keyArn, ciphertext: Buffer.from(response.CiphertextBlob).toString('base64url'),
    };
  }

  async unwrap(wrapped: WrappedKey, identity: PackageIdentity): Promise<Buffer> {
    const ring = this.ring(identity.tenantId);
    const keyArn = wrapped.keyReference;
    requireArn(keyArn);
    if (wrapped.provider !== 'aws-kms' || wrapped.keyVersion !== keyArn || !ring.permittedKeyArns.includes(keyArn)) {
      throw new DomainError('KMS_KEY_MISMATCH', 'Wrapped key is not permitted for this tenant');
    }
    let response;
    try {
      response = await this.client.send(new DecryptCommand({
        KeyId: keyArn,
        CiphertextBlob: Buffer.from(wrapped.ciphertext, 'base64url'),
        EncryptionContext: context(identity),
      }), { abortSignal: AbortSignal.timeout(3000) });
    } catch {
      throw new DomainError('KMS_UNAVAILABLE', 'Content-key service is unavailable');
    }
    if (!response.Plaintext || response.Plaintext.length !== 32 || response.KeyId !== keyArn) throw new DomainError('KMS_DECRYPT_FAILED', 'KMS returned an invalid content key or a different key');
    const dataKey = Buffer.from(response.Plaintext);
    response.Plaintext.fill(0);
    return dataKey;
  }

  async assertActive(reference: string, tenantId: string, _assetId: string, _assetVersion: number, _renditionId: string): Promise<void> {
    const ring = this.ring(tenantId);
    requireArn(reference);
    if (!ring.permittedKeyArns.includes(reference)) throw new DomainError('KMS_KEY_MISMATCH', 'Rendition key is not permitted for this tenant');
    let response;
    try {
      response = await this.client.send(new DescribeKeyCommand({ KeyId: reference }),
        { abortSignal: AbortSignal.timeout(3000) });
    } catch {
      throw new DomainError('KMS_UNAVAILABLE', 'Key status service is unavailable');
    }
    if (response.KeyMetadata?.Arn !== reference || !response.KeyMetadata.Enabled || response.KeyMetadata.KeyState !== 'Enabled' || response.KeyMetadata.KeyUsage !== 'ENCRYPT_DECRYPT') {
      throw new DomainError('KMS_KEY_DISABLED', 'KMS key is unavailable for content encryption');
    }
  }
}
