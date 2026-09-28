import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { DomainError } from '@drm/core';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

export interface AuthenticatedPrincipal {
  readonly tenantId: string;
  readonly externalSubject: string;
}

export interface AccessTokenVerifier {
  verify(authorization: string | undefined): Promise<AuthenticatedPrincipal>;
}

export interface OidcConfiguration {
  readonly issuer: string;
  readonly audience: string;
  readonly jwksUrl: string;
  readonly requiredScope: string;
}

export class OidcAccessTokenVerifier implements AccessTokenVerifier {
  private readonly config: OidcConfiguration;
  private readonly keys: JWTVerifyGetKey;

  constructor(config: OidcConfiguration, keys?: JWTVerifyGetKey) {
    const issuer = new URL(config.issuer);
    const jwks = new URL(config.jwksUrl);
    if (issuer.protocol !== 'https:' || jwks.protocol !== 'https:' || !config.audience || !config.requiredScope) {
      throw new DomainError('INVALID_OIDC_CONFIG', 'OIDC issuer, JWKS, audience, and scope must be trusted HTTPS configuration');
    }
    this.config = config;
    this.keys = keys ?? createRemoteJWKSet(jwks, {
      timeoutDuration: 3000, cacheMaxAge: 300_000, cooldownDuration: 30_000,
    });
  }

  async verify(authorization: string | undefined): Promise<AuthenticatedPrincipal> {
    if (authorization === undefined || authorization.length > 8192) throw new DomainError('UNAUTHENTICATED', 'Valid bearer access token required');
    const match = BEARER.exec(authorization);
    if (!match?.[1]) throw new DomainError('UNAUTHENTICATED', 'Valid bearer access token required');
    try {
      const { payload } = await jwtVerify(match[1], this.keys, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        algorithms: ['RS256', 'ES256'],
        requiredClaims: ['exp', 'iat', 'sub', 'tenant_id'],
        maxTokenAge: '15m',
        clockTolerance: 30,
      });
      if (typeof payload.tenant_id !== 'string' || !UUID.test(payload.tenant_id) ||
          typeof payload.sub !== 'string' || payload.sub.length < 1 || payload.sub.length > 256 ||
          typeof payload.scope !== 'string' || !payload.scope.split(' ').includes(this.config.requiredScope)) {
        throw new DomainError('UNAUTHENTICATED', 'Required tenant, subject, or scope missing');
      }
      return { tenantId: payload.tenant_id, externalSubject: payload.sub };
    } catch (error) {
      if (error instanceof joseErrors.JWKSTimeout) throw new DomainError('AUTH_UNAVAILABLE', 'Identity key service is temporarily unavailable');
      throw new DomainError('UNAUTHENTICATED', 'Valid bearer access token required');
    }
  }
}
