import { createCipheriv, createDecipheriv, createHash, randomBytes, verify } from 'node:crypto';
import { DomainError, requireValue } from './errors.ts';
import { canonicalJson } from './canonical.ts';
import { verifyLicense, type LicenseSigner, type SignedLicense, type TrustedSigningKey } from './license.ts';
import type { Action } from './model.ts';

const MAX_CONTENT_BYTES = 64 * 1024 * 1024;
const MAX_CHUNK_BYTES = 1024 * 1024;
const MAX_CHUNKS = 16_384;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;

export interface PackageIdentity {
  readonly tenantId: string;
  readonly assetId: string;
  readonly assetVersion: string;
  readonly renditionId: string;
  readonly mimeType: string;
}

export interface WrappedKey {
  readonly provider: string;
  readonly keyVersion: string;
  readonly keyReference: string;
  readonly ciphertext: string;
}

export interface KeyWrapper {
  wrap(dataKey: Buffer, identity: PackageIdentity): Promise<WrappedKey>;
  unwrap(wrapped: WrappedKey, identity: PackageIdentity): Promise<Buffer>;
}

export interface ChunkRecord {
  readonly index: number;
  readonly length: number;
  readonly nonce: string;
  readonly tag: string;
  readonly ciphertextSha256: string;
}

export interface PackageManifest {
  readonly formatVersion: 1;
  readonly signingKeyId: string;
  readonly identity: PackageIdentity;
  readonly totalBytes: number;
  readonly chunkSize: number;
  readonly wrappedKey: WrappedKey;
  readonly chunks: readonly ChunkRecord[];
}

export interface SecurePackage {
  readonly manifest: PackageManifest;
  readonly manifestSignature: string;
  readonly ciphertextChunks: readonly string[];
}

function associatedData(identity: PackageIdentity, index: number, length: number): Buffer {
  return Buffer.from(canonicalJson([identity.tenantId, identity.assetId, identity.assetVersion, identity.renditionId, index, length]));
}

function manifestSigningMessage(manifest: PackageManifest): Buffer {
  return createHash('sha256').update('drm-package-manifest-v1\0').update(canonicalJson(manifest)).digest();
}

function validateIdentity(identity: PackageIdentity): void {
  for (const value of Object.values(identity)) requireValue(typeof value === 'string' && value.length > 0 && value.length <= 256, 'INVALID_IDENTITY', 'Package identity fields must be 1–256 characters');
}

export async function createSecurePackage(content: Buffer, identity: PackageIdentity, keys: KeyWrapper, signer: LicenseSigner, chunkSize = MAX_CHUNK_BYTES): Promise<SecurePackage> {
  validateIdentity(identity);
  requireValue(content.length > 0 && content.length <= MAX_CONTENT_BYTES, 'INVALID_CONTENT', 'Content size outside supported range');
  requireValue(Number.isSafeInteger(chunkSize) && chunkSize > 0 && chunkSize <= MAX_CHUNK_BYTES, 'INVALID_CHUNK_SIZE', 'Chunk size outside supported range');
  requireValue(Math.ceil(content.length / chunkSize) <= MAX_CHUNKS, 'INVALID_CHUNK_SIZE', 'Too many chunks');
  requireValue(typeof signer.keyId === 'string' && signer.keyId.length > 0 && signer.keyId.length <= 512, 'INVALID_SIGNING_KEY', 'Signing key reference required');
  const dataKey = randomBytes(32);
  try {
    const wrappedKey = await keys.wrap(dataKey, identity);
    const chunks: ChunkRecord[] = [];
    const ciphertextChunks: string[] = [];
    for (let offset = 0, index = 0; offset < content.length; offset += chunkSize, index++) {
      const plaintext = content.subarray(offset, Math.min(offset + chunkSize, content.length));
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', dataKey, nonce);
      cipher.setAAD(associatedData(identity, index, plaintext.length));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      chunks.push({
        index, length: plaintext.length, nonce: nonce.toString('base64url'),
        tag: cipher.getAuthTag().toString('base64url'),
        ciphertextSha256: createHash('sha256').update(ciphertext).digest('hex'),
      });
      ciphertextChunks.push(ciphertext.toString('base64url'));
    }
    const manifest: PackageManifest = { formatVersion: 1, signingKeyId: signer.keyId, identity, totalBytes: content.length, chunkSize, wrappedKey, chunks };
    validateManifest(manifest, ciphertextChunks.length);
    const signedBytes = Buffer.from(canonicalJson(manifest));
    requireValue(signedBytes.length <= MAX_MANIFEST_BYTES, 'INVALID_PACKAGE', 'Manifest too large');
    const signature = await signer.signEd25519(manifestSigningMessage(manifest));
    requireValue(signature.length === 64, 'INVALID_SIGNATURE', 'Ed25519 signature must be 64 bytes');
    const manifestSignature = signature.toString('base64url');
    return { manifest, manifestSignature, ciphertextChunks };
  } finally {
    dataKey.fill(0);
  }
}

function validateManifest(manifest: PackageManifest, count: number): void {
  requireValue(manifest.formatVersion === 1, 'INVALID_PACKAGE', 'Unsupported package version');
  requireValue(typeof manifest.signingKeyId === 'string' && manifest.signingKeyId.length > 0 && manifest.signingKeyId.length <= 512, 'INVALID_PACKAGE', 'Invalid signing key reference');
  validateIdentity(manifest.identity);
  requireValue(manifest.wrappedKey !== null && typeof manifest.wrappedKey === 'object', 'INVALID_PACKAGE', 'Wrapped key required');
  requireValue(typeof manifest.wrappedKey.provider === 'string' && manifest.wrappedKey.provider.length > 0 && manifest.wrappedKey.provider.length <= 128, 'INVALID_PACKAGE', 'Invalid key provider');
  requireValue(typeof manifest.wrappedKey.keyVersion === 'string' && manifest.wrappedKey.keyVersion.length > 0 && manifest.wrappedKey.keyVersion.length <= 128, 'INVALID_PACKAGE', 'Invalid key version');
  requireValue(typeof manifest.wrappedKey.keyReference === 'string' && manifest.wrappedKey.keyReference.length > 0 && manifest.wrappedKey.keyReference.length <= 512, 'INVALID_PACKAGE', 'Invalid key reference');
  requireValue(typeof manifest.wrappedKey.ciphertext === 'string' && manifest.wrappedKey.ciphertext.length > 0 && manifest.wrappedKey.ciphertext.length <= 8192, 'INVALID_PACKAGE', 'Invalid wrapped key');
  requireValue(Number.isSafeInteger(manifest.totalBytes) && manifest.totalBytes > 0 && manifest.totalBytes <= MAX_CONTENT_BYTES, 'INVALID_PACKAGE', 'Invalid total length');
  requireValue(Number.isSafeInteger(manifest.chunkSize) && manifest.chunkSize > 0 && manifest.chunkSize <= MAX_CHUNK_BYTES, 'INVALID_PACKAGE', 'Invalid chunk size');
  requireValue(count <= MAX_CHUNKS && manifest.chunks.length === count && count === Math.ceil(manifest.totalBytes / manifest.chunkSize), 'INVALID_PACKAGE', 'Invalid chunk count');
  let sum = 0;
  for (let index = 0; index < count; index++) {
    const chunk = manifest.chunks[index];
    requireValue(chunk !== undefined && chunk.index === index && Number.isSafeInteger(chunk.length) && chunk.length > 0 && chunk.length <= manifest.chunkSize, 'INVALID_PACKAGE', 'Invalid chunk metadata');
    requireValue(Buffer.from(chunk.nonce, 'base64url').length === 12 && Buffer.from(chunk.tag, 'base64url').length === 16 && /^[a-f0-9]{64}$/.test(chunk.ciphertextSha256), 'INVALID_PACKAGE', 'Invalid cryptographic metadata');
    sum += chunk.length;
  }
  requireValue(sum === manifest.totalBytes, 'INVALID_PACKAGE', 'Package length mismatch');
}

export async function openLicensedChunk(
  pkg: SecurePackage, index: number, expectedIdentity: PackageIdentity,
  keys: KeyWrapper, manifestSigningKey: TrustedSigningKey, license: SignedLicense,
  licenseSigningKey: TrustedSigningKey, expectedDeviceId: string, trustedNow: string, action: Action,
): Promise<Buffer> {
  requireValue(verifyLicense(license, licenseSigningKey, expectedDeviceId, trustedNow), 'LICENSE_INVALID', 'License is invalid or expired');
  requireValue(pkg !== null && typeof pkg === 'object' && pkg.manifest !== null && typeof pkg.manifest === 'object' && pkg.manifest.wrappedKey !== null && typeof pkg.manifest.wrappedKey === 'object', 'INVALID_PACKAGE', 'Package manifest and wrapped key required');
  requireValue(license.claims.tenantId === expectedIdentity.tenantId && license.claims.assetId === expectedIdentity.assetId &&
    license.claims.assetVersion === expectedIdentity.assetVersion && license.claims.renditionId === expectedIdentity.renditionId &&
    license.claims.rights.includes(action) && license.claims.keyReference === pkg.manifest.wrappedKey.keyReference,
  'LICENSE_SCOPE', 'License does not authorize this rendition, action, or key');
  requireValue(Number.isSafeInteger(index) && index >= 0, 'INVALID_CHUNK', 'Invalid chunk index');
  requireValue(pkg.manifest.signingKeyId === manifestSigningKey.keyId && manifestSigningKey.publicKey.type === 'public' && manifestSigningKey.publicKey.asymmetricKeyType === 'ed25519', 'INVALID_SIGNING_KEY', 'Trusted Ed25519 signing key required');
  const signedBytes = Buffer.from(canonicalJson(pkg.manifest));
  requireValue(signedBytes.length <= MAX_MANIFEST_BYTES, 'INVALID_PACKAGE', 'Manifest too large');
  requireValue(verify(null, manifestSigningMessage(pkg.manifest), manifestSigningKey.publicKey, Buffer.from(pkg.manifestSignature, 'base64url')), 'INVALID_SIGNATURE', 'Package manifest signature invalid');
  validateManifest(pkg.manifest, pkg.ciphertextChunks.length);
  requireValue(canonicalJson(pkg.manifest.identity) === canonicalJson(expectedIdentity), 'IDENTITY_MISMATCH', 'Package identity mismatch');
  const metadata = pkg.manifest.chunks[index];
  const encoded = pkg.ciphertextChunks[index];
  if (metadata === undefined || encoded === undefined) throw new DomainError('INVALID_CHUNK', 'Chunk missing');
  requireValue(encoded.length <= Math.ceil(MAX_CHUNK_BYTES * 4 / 3) + 4, 'INVALID_CHUNK', 'Encoded chunk too large');
  const ciphertext = Buffer.from(encoded, 'base64url');
  requireValue(ciphertext.length === metadata.length, 'INVALID_CHUNK', 'Chunk length mismatch');
  requireValue(createHash('sha256').update(ciphertext).digest('hex') === metadata.ciphertextSha256, 'INVALID_CHUNK', 'Chunk checksum mismatch');
  const dataKey = Buffer.from(await keys.unwrap(pkg.manifest.wrappedKey, pkg.manifest.identity));
  try {
    requireValue(dataKey.length === 32, 'INVALID_KEY', 'Unwrapped key must be 256 bits');
    const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(metadata.nonce, 'base64url'));
    decipher.setAAD(associatedData(pkg.manifest.identity, index, metadata.length));
    decipher.setAuthTag(Buffer.from(metadata.tag, 'base64url'));
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    dataKey.fill(0);
  }
}
