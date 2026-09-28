import { createHmac } from 'node:crypto';
import { DomainError, verifyLicense, type SignedLicense, type TrustedSigningKey } from '@drm/core';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MEDIA_RIGHTS = new Set(['play', 'listen', 'stream']);

export interface AxinomCredential {
  readonly communicationKeyId: string;
  readonly communicationKeyBase64: string;
}

export type AxinomCredentialResolver = (tenantId: string) => Promise<AxinomCredential>;

export interface AxinomPlaybackToken {
  readonly headerName: 'X-AxDRM-Message';
  readonly token: string;
  readonly expiresAt: string;
  readonly contentKeyId: string;
}

function decodeCredential(value: string): Buffer {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new DomainError('AXINOM_CONFIG_INVALID', 'Communication key must be canonical base64 for 32 bytes');
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32 || key.toString('base64') !== value) {
    key.fill(0);
    throw new DomainError('AXINOM_CONFIG_INVALID', 'Communication key must be 32 bytes');
  }
  return key;
}

/** Produces a provider token only after a separate authoritative license decision. */
export class AxinomPlaybackTokenIssuer {
  private readonly credentials: AxinomCredentialResolver;

  constructor(credentials: AxinomCredentialResolver) {
    this.credentials = credentials;
  }

  async issue(
    license: SignedLicense, signingPublicKey: TrustedSigningKey, deviceId: string,
    trustedNow: string, contentKeyId: string,
  ): Promise<AxinomPlaybackToken> {
    if (!verifyLicense(license, signingPublicKey, deviceId, trustedNow)) {
      throw new DomainError('LICENSE_INVALID', 'Verified media license required');
    }
    const claims = license.claims;
    if (!UUID.test(contentKeyId) || claims.keyReference !== `axinom:${contentKeyId.toLowerCase()}`) {
      throw new DomainError('AXINOM_KEY_SCOPE', 'License does not authorize this content key');
    }
    if (claims.offlineUntil !== null || claims.rights.length !== 1 || !MEDIA_RIGHTS.has(claims.rights[0] ?? '')) {
      throw new DomainError('AXINOM_POLICY_UNSUPPORTED', 'Only online playback rights can be translated');
    }
    const now = Date.parse(trustedNow);
    const expiry = Math.min(Date.parse(claims.expiresAt), now + 30_000);
    const duration = Math.floor((expiry - now) / 1000);
    if (!Number.isSafeInteger(duration) || duration < 1) throw new DomainError('LICENSE_EXPIRED', 'No remaining playback window');
    const credential = await this.credentials(claims.tenantId);
    if (!UUID.test(credential.communicationKeyId)) throw new DomainError('AXINOM_CONFIG_INVALID', 'Communication key ID must be a UUID');
    const key = decodeCredential(credential.communicationKeyBase64);
    try {
      const expiresAt = new Date(expiry).toISOString();
      const envelope = {
        version: 1,
        id: claims.licenseId,
        expiration_date: expiresAt,
        com_key_id: credential.communicationKeyId,
        message: {
          type: 'entitlement_message', version: 2,
          license: {
            start_datetime: new Date(now).toISOString(),
            expiration_datetime: expiresAt,
            duration,
            allow_persistence: false,
          },
          content_keys_source: { inline: [{ id: contentKeyId.toLowerCase() }] },
          session: { user_id: claims.subjectId },
        },
      };
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify(envelope)).toString('base64url');
      const signingInput = `${header}.${payload}`;
      const signature = createHmac('sha256', key).update(signingInput).digest('base64url');
      return { headerName: 'X-AxDRM-Message', token: `${signingInput}.${signature}`, expiresAt, contentKeyId: contentKeyId.toLowerCase() };
    } finally {
      key.fill(0);
    }
  }
}
