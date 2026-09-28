import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { TextDecoder } from 'node:util';
import type { Pool } from 'pg';
import { ACTIONS, DomainError, type Action, type SignedLicense } from '@drm/core';
import { issueDeviceChallenge, issueDeviceEnrollmentChallenge, registerDevice, revokeOwnedDevice, type DatabaseLicenseRequest, type PostgresAssetPublisher, type PostgresLicenseService, type PublishAssetInput, type RegisterDeviceInput, withTenantTransaction } from '@drm/postgres';
import type { AccessTokenVerifier } from './auth.ts';
import { consumeUserRateLimit, type LimitedOperation } from './rate-limit.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_BODY_BYTES = 4096;
const MAX_PUBLISH_CONTENT_BYTES = 8 * 1024 * 1024;
const MAX_PUBLISH_BODY_BYTES = 11 * 1024 * 1024;

export interface LicenseApiDependencies {
  readonly auth: AccessTokenVerifier;
  readonly resolveUser: (tenantId: string, externalSubject: string) => Promise<string>;
  readonly consumeRate: (tenantId: string, userId: string, operation: LimitedOperation) => Promise<void>;
  readonly issueChallenge: (tenantId: string, userId: string, deviceId: string) => Promise<string>;
  readonly issueEnrollmentChallenge: (tenantId: string, userId: string, publicKeyPem: string, deviceClass: string) => Promise<string>;
  readonly registerDevice: (input: RegisterDeviceInput) => Promise<string>;
  readonly revokeDevice: (tenantId: string, userId: string, deviceId: string) => Promise<void>;
  readonly licenses: Pick<PostgresLicenseService, 'issue'>;
  readonly publishAuth?: AccessTokenVerifier;
  readonly publisher?: Pick<PostgresAssetPublisher, 'publish'>;
  readonly ready?: () => Promise<void>;
  readonly logError?: (event: { requestId: string; errorName: string }) => void;
}

export function createPostgresLicenseApi(
  pool: Pool, auth: AccessTokenVerifier, licenses: PostgresLicenseService,
  publishing?: { auth: AccessTokenVerifier; publisher: PostgresAssetPublisher },
): Server {
  return createLicenseApiServer({
    auth,
    async resolveUser(tenantId, externalSubject) {
      return withTenantTransaction(pool, tenantId, async (client) => {
        const result = await client.query<{ id: string }>(
          `SELECT id FROM drm.users
           WHERE tenant_id = $1 AND external_subject = $2 AND status = 'active'`,
          [tenantId, externalSubject],
        );
        if (!result.rows[0]) throw new DomainError('ACCESS_DENIED', 'Active account required');
        return result.rows[0].id;
      });
    },
    consumeRate: (tenantId, userId, operation) => consumeUserRateLimit(pool, tenantId, userId, operation,
      operation === 'license-issue' ? 30 : operation === 'asset-publish' ? 3 : 10),
    issueChallenge: (tenantId, userId, deviceId) => issueDeviceChallenge(pool, tenantId, userId, deviceId),
    issueEnrollmentChallenge: (tenantId, userId, publicKeyPem, deviceClass) => issueDeviceEnrollmentChallenge(pool, tenantId, userId, publicKeyPem, deviceClass),
    registerDevice: (input) => registerDevice(pool, input),
    revokeDevice: (tenantId, userId, deviceId) => revokeOwnedDevice(pool, tenantId, userId, deviceId),
    licenses,
    ...(publishing ? { publishAuth: publishing.auth, publisher: publishing.publisher } : {}),
    ready: async () => { await pool.query('SELECT 1'); },
  });
}

function oneAuthorizationHeader(request: IncomingMessage): string | undefined {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === 'authorization') count++;
  }
  if (count !== 1 || Array.isArray(request.headers.authorization)) throw new DomainError('UNAUTHENTICATED', 'One bearer authorization header required');
  return request.headers.authorization;
}

async function readJson(request: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<Record<string, unknown>> {
  const contentType = request.headers['content-type'];
  if (typeof contentType !== 'string' || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType)) {
    throw new DomainError('INVALID_REQUEST', 'JSON content type required');
  }
  const declaredLength = request.headers['content-length'];
  if (declaredLength !== undefined && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maxBytes)) {
    throw new DomainError('INVALID_REQUEST', 'Request body too large');
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maxBytes) throw new DomainError('INVALID_REQUEST', 'Request body too large');
    chunks.push(bytes);
  }
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected JSON object');
    return value as Record<string, unknown>;
  } catch {
    throw new DomainError('INVALID_REQUEST', 'Valid JSON object required');
  }
}

function publishingBody(body: Record<string, unknown>): Pick<PublishAssetInput, 'content' | 'mimeType' | 'policy'> {
  exactFields(body, ['contentBase64', 'mimeType', 'policy']);
  const encoded = body.contentBase64;
  if (typeof encoded !== 'string' || encoded.length < 4 || encoded.length > Math.ceil(MAX_PUBLISH_CONTENT_BYTES / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new DomainError('INVALID_REQUEST', 'Valid bounded base64 asset content required');
  }
  const content = Buffer.from(encoded, 'base64');
  if (content.length < 1 || content.length > MAX_PUBLISH_CONTENT_BYTES || content.toString('base64') !== encoded ||
      typeof body.mimeType !== 'string' || body.policy === null || typeof body.policy !== 'object' || Array.isArray(body.policy)) {
    throw new DomainError('INVALID_REQUEST', 'Valid content, MIME type, and policy required');
  }
  return { content, mimeType: body.mimeType, policy: body.policy as PublishAssetInput['policy'] };
}

function exactFields(value: Record<string, unknown>, required: readonly string[]): void {
  if (Object.keys(value).length !== required.length || required.some((field) => !Object.hasOwn(value, field))) {
    throw new DomainError('INVALID_REQUEST', 'Unexpected or missing request fields');
  }
}

function uuid(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new DomainError('INVALID_REQUEST', 'UUID field required');
  return value;
}

function challengeBody(body: Record<string, unknown>): string {
  exactFields(body, ['deviceId']);
  return uuid(body.deviceId);
}

function enrollmentChallengeBody(body: Record<string, unknown>): { publicKeyPem: string; deviceClass: string } {
  exactFields(body, ['publicKeyPem', 'deviceClass']);
  if (typeof body.publicKeyPem !== 'string' || typeof body.deviceClass !== 'string') {
    throw new DomainError('INVALID_REQUEST', 'Public key and device class required');
  }
  return { publicKeyPem: body.publicKeyPem, deviceClass: body.deviceClass };
}

function registrationBody(body: Record<string, unknown>): Omit<RegisterDeviceInput, 'tenantId' | 'userId'> {
  exactFields(body, ['publicKeyPem', 'deviceClass', 'proof']);
  const base = enrollmentChallengeBody({ publicKeyPem: body.publicKeyPem, deviceClass: body.deviceClass });
  const proof = body.proof;
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) throw new DomainError('INVALID_REQUEST', 'Device proof required');
  const fields = proof as Record<string, unknown>;
  exactFields(fields, ['challenge', 'signature']);
  if (typeof fields.challenge !== 'string' || typeof fields.signature !== 'string') throw new DomainError('INVALID_REQUEST', 'Device proof required');
  return { ...base, challenge: fields.challenge, signature: fields.signature };
}

function licenseBody(body: Record<string, unknown>): Omit<DatabaseLicenseRequest, 'tenantId' | 'authenticatedUserId'> {
  exactFields(body, ['entitlementId', 'deviceId', 'renditionId', 'action', 'proof', 'requestedSeconds']);
  const action = body.action;
  if (typeof action !== 'string' || !ACTIONS.includes(action as Action)) throw new DomainError('INVALID_REQUEST', 'Known action required');
  const proof = body.proof;
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) throw new DomainError('INVALID_REQUEST', 'Device proof required');
  const proofFields = proof as Record<string, unknown>;
  exactFields(proofFields, ['challenge', 'signature']);
  if (typeof proofFields.challenge !== 'string' || proofFields.challenge.length < 16 || proofFields.challenge.length > 256 ||
      typeof proofFields.signature !== 'string' || proofFields.signature.length < 1 || proofFields.signature.length > 256) {
    throw new DomainError('INVALID_REQUEST', 'Valid device proof required');
  }
  if (!Number.isSafeInteger(body.requestedSeconds) || (body.requestedSeconds as number) < 1 || (body.requestedSeconds as number) > 3600) {
    throw new DomainError('INVALID_REQUEST', 'License duration must be 1–3600 seconds');
  }
  return {
    entitlementId: uuid(body.entitlementId), deviceId: uuid(body.deviceId), renditionId: uuid(body.renditionId),
    action: action as Action,
    proof: { challenge: proofFields.challenge, signature: proofFields.signature },
    requestedSeconds: body.requestedSeconds as number,
  };
}

function sendJson(response: ServerResponse, status: number, body: Record<string, unknown>, requestId: string): void {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Request-Id': requestId,
  });
  response.end(JSON.stringify(body));
}

function errorStatus(error: DomainError): number {
  if (error.code === 'UNAUTHENTICATED') return 401;
  if (error.code === 'AUTH_UNAVAILABLE') return 503;
  if (error.code === 'RATE_LIMITED' || error.code === 'CHALLENGE_LIMIT') return 429;
  if (error.code === 'INVALID_REQUEST') return 400;
  if (error.code.startsWith('INVALID_')) return 400;
  if (error.code.startsWith('KMS_') || error.code === 'BAO_UNAVAILABLE' || error.code === 'BAO_KEY_DISABLED') return 503;
  return 403;
}

export function createLicenseApiServer(dependencies: LicenseApiDependencies): Server {
  const server = createServer((request, response) => {
    const requestId = randomUUID();
    void (async () => {
      const url = new URL(request.url ?? '/', 'http://localhost');
      if (request.method === 'GET' && url.pathname === '/health/live' && !url.search) {
        sendJson(response, 200, { status: 'live' }, requestId);
        return;
      }
      if (request.method === 'GET' && url.pathname === '/health/ready' && !url.search) {
        try {
          await dependencies.ready?.();
          sendJson(response, 200, { status: 'ready' }, requestId);
        } catch {
          sendJson(response, 503, { error: 'NOT_READY' }, requestId);
        }
        return;
      }
      const revokeMatch = request.method === 'DELETE' ? /^\/v1\/devices\/([^/]+)$/.exec(url.pathname) : null;
      const postRoute = request.method === 'POST' && [
        '/v1/device-enrollment-challenges', '/v1/devices', '/v1/device-challenges', '/v1/licenses',
      ].includes(url.pathname);
      const publishRoute = request.method === 'POST' && url.pathname === '/v1/assets' &&
        dependencies.publishAuth !== undefined && dependencies.publisher !== undefined;
      if (url.search || (!postRoute && !revokeMatch && !publishRoute)) {
        sendJson(response, 404, { error: 'NOT_FOUND' }, requestId);
        return;
      }
      const principal = await (publishRoute ? dependencies.publishAuth! : dependencies.auth).verify(oneAuthorizationHeader(request));
      const userId = await dependencies.resolveUser(principal.tenantId, principal.externalSubject);
      if (revokeMatch) {
        const deviceId = uuid(revokeMatch[1]);
        await dependencies.revokeDevice(principal.tenantId, userId, deviceId);
        response.writeHead(204, { 'Cache-Control': 'no-store', 'X-Request-Id': requestId });
        response.end();
        return;
      }
      const body = await readJson(request, publishRoute ? MAX_PUBLISH_BODY_BYTES : MAX_BODY_BYTES);
      if (publishRoute) {
        const input = publishingBody(body);
        await dependencies.consumeRate(principal.tenantId, userId, 'asset-publish');
        const published = await dependencies.publisher!.publish({ tenantId: principal.tenantId, ownerUserId: userId, ...input });
        sendJson(response, 201, { asset: published }, requestId);
        return;
      }
      if (url.pathname === '/v1/device-enrollment-challenges') {
        const input = enrollmentChallengeBody(body);
        await dependencies.consumeRate(principal.tenantId, userId, 'device-challenge');
        const challenge = await dependencies.issueEnrollmentChallenge(principal.tenantId, userId, input.publicKeyPem, input.deviceClass);
        sendJson(response, 201, { challenge, expiresInSeconds: 120 }, requestId);
        return;
      }
      if (url.pathname === '/v1/devices') {
        const input = registrationBody(body);
        await dependencies.consumeRate(principal.tenantId, userId, 'device-challenge');
        const deviceId = await dependencies.registerDevice({ tenantId: principal.tenantId, userId, ...input });
        sendJson(response, 201, { deviceId, trust: 'software' }, requestId);
        return;
      }
      if (url.pathname === '/v1/device-challenges') {
        const deviceId = challengeBody(body);
        await dependencies.consumeRate(principal.tenantId, userId, 'device-challenge');
        const challenge = await dependencies.issueChallenge(principal.tenantId, userId, deviceId);
        sendJson(response, 201, { challenge, expiresInSeconds: 120 }, requestId);
        return;
      }
      const input = licenseBody(body);
      await dependencies.consumeRate(principal.tenantId, userId, 'license-issue');
      const license: SignedLicense = await dependencies.licenses.issue({
        ...input, tenantId: principal.tenantId, authenticatedUserId: userId,
      });
      sendJson(response, 201, { license }, requestId);
    })().catch((error: unknown) => {
      if (response.writableEnded || response.destroyed) return;
      if (error instanceof DomainError) {
        const status = errorStatus(error);
        if (status === 429) response.setHeader('Retry-After', '60');
        sendJson(response, status, { error: error.code }, requestId);
        return;
      }
      const event = { requestId, errorName: error instanceof Error ? error.name : 'UnknownError' };
      if (dependencies.logError) dependencies.logError(event);
      else process.stderr.write(`${JSON.stringify({ event: 'api.error', ...event })}\n`);
      sendJson(response, 500, { error: 'INTERNAL_ERROR' }, requestId);
    });
  });
  server.maxHeadersCount = 50;
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;
  return server;
}
