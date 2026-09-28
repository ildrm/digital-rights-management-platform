import { canonicalJson, DomainError, type KeyWrapper, type LicenseSigner, type PackageIdentity, type WrappedKey } from '@drm/core';

const KEY_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/;
const KEY_REFERENCE = /^openbao:transit:encrypt:([a-zA-Z0-9][a-zA-Z0-9_-]{0,127})$/;
const CIPHERTEXT = /^vault:v([1-9][0-9]*):([A-Za-z0-9+/]+={0,2})$/;
const SIGNATURE = /^vault:v([1-9][0-9]*):([A-Za-z0-9+/]+={0,2})$/;

export interface TenantTransitKeyRing {
  readonly activeKeyName: string;
  readonly permittedKeyNames: readonly string[];
}

function keyName(name: string): void {
  if (!KEY_NAME.test(name)) throw new DomainError('INVALID_BAO_KEY', 'OpenBao Transit key name is invalid');
}

function identityContext(identity: PackageIdentity): { context: string; associated_data: string } {
  return {
    context: Buffer.from(identity.tenantId).toString('base64'),
    associated_data: Buffer.from(canonicalJson([
      identity.tenantId, identity.assetId, identity.assetVersion, identity.renditionId,
    ])).toString('base64'),
  };
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned an invalid response');
  }
  return value as Record<string, unknown>;
}

export class OpenBaoTransitClient {
  private readonly endpoint: URL;
  private readonly token: string;
  private readonly request: typeof fetch;

  constructor(endpoint: string, token: string, request: typeof fetch = fetch, allowInsecureLoopback = false) {
    const url = new URL(endpoint);
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !(allowInsecureLoopback && url.protocol === 'http:' && loopback)) ||
        url.username || url.password || url.search || url.hash || url.pathname !== '/' || !token || token.length > 8192) {
      throw new DomainError('INVALID_BAO_CONFIG', 'OpenBao requires a trusted HTTPS endpoint and token');
    }
    this.endpoint = url;
    this.token = token;
    this.request = request;
  }

  async readKey(name: string): Promise<Record<string, unknown>> {
    keyName(name);
    return this.call('GET', `transit/keys/${name}`);
  }

  async sign(name: string, version: number, input: Buffer): Promise<string> {
    keyName(name);
    if (!Number.isSafeInteger(version) || version < 1 || input.length !== 32) {
      throw new DomainError('INVALID_SIGNING_MESSAGE', 'Pinned signing version and 32-byte digest required');
    }
    const data = await this.call('POST', `transit/sign/${name}`, { input: input.toString('base64'), key_version: version });
    if (typeof data.signature !== 'string') throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned no signature');
    return data.signature;
  }

  async encrypt(name: string, plaintext: Buffer, identity: PackageIdentity): Promise<string> {
    keyName(name);
    if (plaintext.length !== 32) throw new DomainError('INVALID_KEY', 'Content key must be 256 bits');
    const data = await this.call('POST', `transit/encrypt/${name}`, {
      plaintext: plaintext.toString('base64'), ...identityContext(identity),
    });
    if (typeof data.ciphertext !== 'string') throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned no ciphertext');
    return data.ciphertext;
  }

  async decrypt(name: string, ciphertext: string, identity: PackageIdentity): Promise<Buffer> {
    keyName(name);
    const data = await this.call('POST', `transit/decrypt/${name}`, {
      ciphertext, ...identityContext(identity),
    });
    if (typeof data.plaintext !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data.plaintext)) {
      throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned invalid plaintext');
    }
    const key = Buffer.from(data.plaintext, 'base64');
    if (key.length !== 32) throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned a key of the wrong length');
    return key;
  }

  private async call(method: 'GET' | 'POST', path: string, payload?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const url = new URL(`v1/${path}`, this.endpoint);
    let response: Response;
    try {
      response = await this.request(url, {
        method,
        headers: { 'X-Vault-Token': this.token, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
        ...(payload ? { body: JSON.stringify(payload) } : {}),
        signal: AbortSignal.timeout(3000),
      });
    } catch {
      throw new DomainError('BAO_UNAVAILABLE', 'OpenBao is unavailable');
    }
    if (!response.ok) {
      throw new DomainError(response.status >= 500 ? 'BAO_UNAVAILABLE' : 'BAO_DENIED', 'OpenBao rejected the operation');
    }
    const length = response.headers.get('content-length');
    if (length && Number(length) > 16_384) throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao response is too large');
    let data: unknown;
    try {
      const body = await response.text();
      if (body.length > 16_384) throw new Error('Response too large');
      data = JSON.parse(body);
    } catch {
      throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned malformed JSON');
    }
    return object(object(data).data);
  }
}

export class OpenBaoLicenseSigner implements LicenseSigner {
  readonly keyId: string;
  private readonly client: OpenBaoTransitClient;
  private readonly keyName: string;
  private readonly version: number;

  constructor(client: OpenBaoTransitClient, signingKeyName: string, version: number) {
    keyName(signingKeyName);
    if (!Number.isSafeInteger(version) || version < 1) throw new DomainError('INVALID_BAO_KEY', 'Signing key version must be pinned');
    this.client = client;
    this.keyName = signingKeyName;
    this.version = version;
    this.keyId = `openbao:transit:sign:${signingKeyName}:v${version}`;
  }

  async signEd25519(message: Buffer): Promise<Buffer> {
    const encoded = await this.client.sign(this.keyName, this.version, message);
    const match = SIGNATURE.exec(encoded);
    if (!match || Number(match[1]) !== this.version) throw new DomainError('BAO_SIGNATURE_INVALID', 'OpenBao used an unexpected signing key version');
    const signature = Buffer.from(match[2]!, 'base64');
    if (signature.length !== 64 || signature.toString('base64') !== match[2]) {
      throw new DomainError('BAO_SIGNATURE_INVALID', 'OpenBao returned an invalid Ed25519 signature');
    }
    return signature;
  }
}

export class OpenBaoKeyWrapper implements KeyWrapper {
  private readonly client: OpenBaoTransitClient;
  private readonly resolveRing: (tenantId: string) => TenantTransitKeyRing;

  constructor(client: OpenBaoTransitClient, resolveRing: (tenantId: string) => TenantTransitKeyRing) {
    this.client = client;
    this.resolveRing = resolveRing;
  }

  private ring(tenantId: string): TenantTransitKeyRing {
    const ring = this.resolveRing(tenantId);
    if (!ring || !Array.isArray(ring.permittedKeyNames) || !ring.permittedKeyNames.includes(ring.activeKeyName)) {
      throw new DomainError('INVALID_BAO_KEY', 'Tenant key ring is missing or inconsistent');
    }
    keyName(ring.activeKeyName);
    for (const name of ring.permittedKeyNames) keyName(name);
    return ring;
  }

  async wrap(dataKey: Buffer, identity: PackageIdentity): Promise<WrappedKey> {
    const name = this.ring(identity.tenantId).activeKeyName;
    await this.assertTransitKey(name);
    const ciphertext = await this.client.encrypt(name, dataKey, identity);
    const match = CIPHERTEXT.exec(ciphertext);
    if (!match || ciphertext.length > 8192) throw new DomainError('BAO_RESPONSE_INVALID', 'OpenBao returned invalid ciphertext');
    return {
      provider: 'openbao-transit', keyVersion: `v${match[1]}`,
      keyReference: `openbao:transit:encrypt:${name}`, ciphertext,
    };
  }

  async unwrap(wrapped: WrappedKey, identity: PackageIdentity): Promise<Buffer> {
    const reference = KEY_REFERENCE.exec(wrapped.keyReference);
    const ciphertext = CIPHERTEXT.exec(wrapped.ciphertext);
    if (wrapped.provider !== 'openbao-transit' || !reference || !ciphertext ||
        wrapped.keyVersion !== `v${ciphertext[1]}` || !this.ring(identity.tenantId).permittedKeyNames.includes(reference[1]!)) {
      throw new DomainError('BAO_KEY_MISMATCH', 'Wrapped key is not permitted for this tenant');
    }
    return this.client.decrypt(reference[1]!, wrapped.ciphertext, identity);
  }

  async assertActive(reference: string, tenantId: string, _assetId: string, _assetVersion: number, _renditionId: string): Promise<void> {
    const match = KEY_REFERENCE.exec(reference);
    if (!match || !this.ring(tenantId).permittedKeyNames.includes(match[1]!)) {
      throw new DomainError('BAO_KEY_MISMATCH', 'Rendition key is not permitted for this tenant');
    }
    await this.assertTransitKey(match[1]!);
  }

  private async assertTransitKey(name: string): Promise<void> {
    const data = await this.client.readKey(name);
    if (data.type !== 'aes256-gcm96' || data.derived !== true || data.supports_encryption !== true ||
        data.supports_decryption !== true || data.deletion_allowed === true) {
      throw new DomainError('BAO_KEY_DISABLED', 'OpenBao key is not an active derived AES-256-GCM key');
    }
  }
}
