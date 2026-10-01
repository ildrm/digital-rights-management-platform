import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, hkdfSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { canonicalJson, DomainError, type KeyWrapper, type LicenseSigner, type PackageIdentity, type WrappedKey } from '@drm/core';

const VERSION = /^[a-zA-Z0-9_-]{1,32}$/;
const TENANT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class LocalLicenseSigner implements LicenseSigner {
  readonly keyId: string;
  readonly publicKey: KeyObject;
  private readonly privateKey: KeyObject;

  constructor(pem: string, version: string) {
    if (!VERSION.test(version)) throw new DomainError('INVALID_SIGNING_KEY', 'Invalid local signing key version');
    this.privateKey = createPrivateKey(pem);
    if (this.privateKey.asymmetricKeyType !== 'ed25519') throw new DomainError('INVALID_SIGNING_KEY', 'An Ed25519 private key is required');
    this.publicKey = createPublicKey(this.privateKey);
    this.keyId = `local:sign:${version}`;
  }

  async signEd25519(message: Buffer): Promise<Buffer> {
    if (!Buffer.isBuffer(message) || message.length !== 32) throw new DomainError('INVALID_SIGNING_MESSAGE', 'A 32-byte digest is required');
    return sign(null, message, this.privateKey);
  }
}

export class LocalKeyWrapper implements KeyWrapper {
  readonly keyReference: string;
  private readonly rootKey: Buffer;
  private readonly version: string;

  constructor(rootKey: Buffer, version: string) {
    if (!Buffer.isBuffer(rootKey) || rootKey.length !== 32 || !VERSION.test(version)) {
      throw new DomainError('INVALID_KEY', 'A 32-byte wrapping key and version are required');
    }
    this.rootKey = Buffer.from(rootKey);
    this.version = version;
    this.keyReference = `local:wrap:${version}`;
  }

  private derive(tenantId: string): Buffer {
    if (!TENANT.test(tenantId)) throw new DomainError('INVALID_IDENTITY', 'Tenant ID must be a UUID');
    return Buffer.from(hkdfSync('sha256', this.rootKey, Buffer.from(tenantId.toLowerCase()), Buffer.from('drm-local-wrap-v1'), 32));
  }

  private aad(identity: PackageIdentity): Buffer {
    return Buffer.from(canonicalJson([identity.tenantId, identity.assetId, identity.assetVersion, identity.renditionId]));
  }

  async wrap(dataKey: Buffer, identity: PackageIdentity): Promise<WrappedKey> {
    if (!Buffer.isBuffer(dataKey) || dataKey.length !== 32) throw new DomainError('INVALID_KEY', 'Content key must be 32 bytes');
    const key = this.derive(identity.tenantId);
    try {
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(this.aad(identity));
      const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);
      return {
        provider: 'local-aes256-gcm', keyVersion: this.version, keyReference: this.keyReference,
        ciphertext: Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]).toString('base64url'),
      };
    } finally {
      key.fill(0);
    }
  }

  async unwrap(wrapped: WrappedKey, identity: PackageIdentity): Promise<Buffer> {
    if (wrapped.provider !== 'local-aes256-gcm' || wrapped.keyVersion !== this.version ||
        wrapped.keyReference !== this.keyReference || !/^[A-Za-z0-9_-]{80}$/.test(wrapped.ciphertext)) {
      throw new DomainError('KEY_MISMATCH', 'Wrapped key is not accepted by the configured local key');
    }
    const bytes = Buffer.from(wrapped.ciphertext, 'base64url');
    if (bytes.length !== 60 || bytes.toString('base64url') !== wrapped.ciphertext) throw new DomainError('KEY_MISMATCH', 'Wrapped key encoding is invalid');
    const key = this.derive(identity.tenantId);
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
      decipher.setAAD(this.aad(identity));
      decipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]);
    } catch {
      throw new DomainError('KEY_MISMATCH', 'Wrapped key authentication failed');
    } finally {
      key.fill(0);
    }
  }

  async assertActive(reference: string, tenantId: string, _assetId: string, _assetVersion: number, _renditionId: string): Promise<void> {
    this.derive(tenantId).fill(0);
    if (reference !== this.keyReference) throw new DomainError('KEY_MISMATCH', 'Rendition key is not active');
  }
}
