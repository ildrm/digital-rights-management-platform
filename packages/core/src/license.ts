import { createHash, randomUUID, verify, type KeyObject } from 'node:crypto';
import { DomainError, requireValue } from './errors.ts';
import { evaluateAccess, type AccessRequest } from './entitlement.ts';
import { ACTIONS, type Action } from './model.ts';
import { canonicalJson } from './canonical.ts';

export interface DeviceProof {
  readonly challenge: string;
  readonly signature: string;
}

export interface ChallengeStore {
  consume(tenantId: string, deviceId: string, challenge: string): Promise<boolean>;
}

export interface LicenseSigner {
  readonly keyId: string;
  signEd25519(message: Buffer): Promise<Buffer>;
}

export interface TrustedSigningKey {
  readonly keyId: string;
  readonly publicKey: KeyObject;
}

export interface LicenseClaims {
  readonly formatVersion: 1;
  readonly licenseId: string;
  readonly tenantId: string;
  readonly assetId: string;
  readonly assetVersion: string;
  readonly renditionId: string;
  readonly subjectId: string;
  readonly deviceId: string;
  readonly rights: readonly Action[];
  readonly issuedAt: string;
  readonly notBefore: string;
  readonly expiresAt: string;
  readonly offlineUntil: string | null;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly keyReference: string;
  readonly nonce: string;
  readonly issuer: string;
  readonly signingKeyId: string;
}

export interface SignedLicense {
  readonly claims: LicenseClaims;
  readonly signature: string;
  readonly algorithm: 'Ed25519';
}

function signingMessage(claims: LicenseClaims): Buffer {
  return createHash('sha256').update('drm-license-v1\0').update(canonicalJson(claims)).digest();
}

const CLAIM_KEYS: readonly (keyof LicenseClaims)[] = [
  'formatVersion', 'licenseId', 'tenantId', 'assetId', 'assetVersion', 'renditionId',
  'subjectId', 'deviceId', 'rights', 'issuedAt', 'notBefore', 'expiresAt',
  'offlineUntil', 'policyId', 'policyVersion', 'keyReference', 'nonce', 'issuer', 'signingKeyId',
];

function instant(value: unknown): number | undefined {
  if (typeof value !== 'string') return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : undefined;
}

function validClaims(claims: LicenseClaims): boolean {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims) ||
      Object.keys(claims).length !== CLAIM_KEYS.length || !CLAIM_KEYS.every((key) => Object.hasOwn(claims, key)) ||
      claims.formatVersion !== 1 || !Number.isSafeInteger(claims.policyVersion) || claims.policyVersion < 1 ||
      !Array.isArray(claims.rights) || claims.rights.length < 1 || claims.rights.length > ACTIONS.length ||
      !claims.rights.every((right) => ACTIONS.includes(right)) || new Set(claims.rights).size !== claims.rights.length) return false;
  for (const key of ['licenseId', 'tenantId', 'assetId', 'assetVersion', 'renditionId', 'subjectId',
    'deviceId', 'policyId', 'keyReference', 'nonce', 'issuer', 'signingKeyId'] as const) {
    const value = claims[key];
    if (typeof value !== 'string' || value.length < 1 || value.length > 512) return false;
  }
  const issued = instant(claims.issuedAt);
  const start = instant(claims.notBefore);
  const end = instant(claims.expiresAt);
  if (issued === undefined || start === undefined || end === undefined || issued > start || start >= end) return false;
  if (claims.offlineUntil !== null) {
    const offlineEnd = instant(claims.offlineUntil);
    if (offlineEnd === undefined || offlineEnd <= start || offlineEnd > end) return false;
  }
  return true;
}

export interface IssueLicenseInput extends AccessRequest {
  readonly renditionId: string;
  readonly deviceProof: DeviceProof;
  readonly keyReference: string;
  readonly issuer: string;
  readonly requestedSeconds: number;
}

export class LicenseIssuer {
  private readonly signer: LicenseSigner;
  private readonly challenges: ChallengeStore;
  private readonly trustedTime: () => string;

  constructor(signer: LicenseSigner, challenges: ChallengeStore, trustedTime: () => string) {
    requireValue(signer.keyId.length > 0, 'INVALID_SIGNING_KEY', 'Signing key reference required');
    this.signer = signer;
    this.challenges = challenges;
    this.trustedTime = trustedTime;
  }

  async issue(input: IssueLicenseInput): Promise<SignedLicense> {
    const trustedNow = this.trustedTime();
    const decision = evaluateAccess({ ...input, context: { ...input.context, now: trustedNow } });
    if (!decision.allowed) throw new DomainError('ACCESS_DENIED', decision.reasons.join('; '));
    requireValue(input.context.online, 'ONLINE_REQUIRED', 'Issuance requires online authorization');
    requireValue(Number.isSafeInteger(input.requestedSeconds) && input.requestedSeconds > 0 && input.requestedSeconds <= 3600, 'INVALID_DURATION', 'License duration must be 1–3600 seconds');
    requireValue(input.keyReference.length > 0 && input.issuer.length > 0, 'INVALID_ISSUER', 'Issuer and key reference required');
    requireValue(input.deviceProof.challenge.length >= 16 && input.deviceProof.challenge.length <= 256 && input.deviceProof.signature.length <= 256, 'DEVICE_PROOF_INVALID', 'Invalid device proof encoding');
    const proof = Buffer.from(input.deviceProof.signature, 'base64url');
    const validProof = verify(null, Buffer.from(input.deviceProof.challenge, 'utf8'), input.device.publicKeyPem, proof);
    requireValue(validProof, 'DEVICE_PROOF_INVALID', 'Device signature is invalid');
    requireValue(await this.challenges.consume(input.device.tenantId, input.device.id, input.deviceProof.challenge), 'DEVICE_PROOF_REPLAY', 'Device challenge is expired or already consumed');
    const issued = Date.parse(trustedNow);
    const expiry = Math.min(
      issued + input.requestedSeconds * 1000,
      input.entitlement.validUntil === undefined ? Infinity : Date.parse(input.entitlement.validUntil),
      input.policy.constraints.expiresAt === undefined ? Infinity : Date.parse(input.policy.constraints.expiresAt),
    );
    requireValue(expiry > issued, 'LICENSE_EXPIRED', 'No remaining access window');
    const offlineUntil = input.policy.constraints.offlineSeconds === undefined ? null : new Date(Math.min(expiry, issued + input.policy.constraints.offlineSeconds * 1000)).toISOString();
    const claims: LicenseClaims = {
      formatVersion: 1, licenseId: randomUUID(), tenantId: input.policy.tenantId,
      assetId: input.policy.assetId, assetVersion: input.assetVersion, renditionId: input.renditionId,
      subjectId: input.principal.id, deviceId: input.device.id, rights: [input.action],
      issuedAt: new Date(issued).toISOString(), notBefore: new Date(issued).toISOString(),
      expiresAt: new Date(expiry).toISOString(), offlineUntil,
      policyId: input.policy.id, policyVersion: input.policy.version,
      keyReference: input.keyReference, nonce: randomUUID(), issuer: input.issuer,
      signingKeyId: this.signer.keyId,
    };
    const signature = await this.signer.signEd25519(signingMessage(claims));
    requireValue(signature.length === 64, 'INVALID_SIGNATURE', 'Ed25519 signature must be 64 bytes');
    return { claims, signature: signature.toString('base64url'), algorithm: 'Ed25519' };
  }
}

export function verifyLicense(license: SignedLicense, signingKey: TrustedSigningKey, expectedDeviceId: string, trustedNow: string): boolean {
  if (!license || typeof license !== 'object' || license.algorithm !== 'Ed25519' || !validClaims(license.claims) ||
      !signingKey || license.claims.signingKeyId !== signingKey.keyId ||
      signingKey.publicKey?.type !== 'public' || signingKey.publicKey.asymmetricKeyType !== 'ed25519' ||
      license.claims.deviceId !== expectedDeviceId || typeof license.signature !== 'string' ||
      !/^[A-Za-z0-9_-]{86}$/.test(license.signature)) return false;
  const now = instant(trustedNow);
  if (now === undefined || now < Date.parse(license.claims.notBefore) || now >= Date.parse(license.claims.expiresAt)) return false;
  const signature = Buffer.from(license.signature, 'base64url');
  if (signature.length !== 64 || signature.toString('base64url') !== license.signature) return false;
  try {
    return verify(null, signingMessage(license.claims), signingKey.publicKey, signature);
  } catch {
    return false;
  }
}
