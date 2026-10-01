import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { TextDecoder } from 'node:util';
import type { Pool } from 'pg';
import { ACTIONS, DomainError, type Action, type SignedLicense } from '@drm/core';
import { issueDeviceChallenge, issueDeviceEnrollmentChallenge, registerDevice, revokeOwnedDevice, PostgresCatalog, type AdminGrantInput, type PostgresAdministrationService, type CreateOfferInput, type PostgresCommerceService, type DatabaseLicenseRequest, type PostgresAssetPublisher, type PostgresLicenseService, type PostgresPackageReader, type PublishAssetInput, type RegisterDeviceInput, withTenantTransaction } from '@drm/postgres';
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
  readonly publisher?: Pick<PostgresAssetPublisher, 'publish' | 'status'>;
  readonly packageReader?: Pick<PostgresPackageReader, 'read'>;
  readonly catalog?: Pick<PostgresCatalog, 'owned' | 'library'>;
  readonly commerce?: Pick<PostgresCommerceService, 'createOffer' | 'disableOffer' | 'listOffers' | 'createOrder' | 'order' | 'checkout' | 'reconcileOrder' | 'acceptWebhook'>;
  readonly adminAuth?: AccessTokenVerifier;
  readonly administration?: Pick<PostgresAdministrationService, 'provisionUser' | 'setUserStatus' | 'grant' | 'revokeGrant'>;
  readonly ready?: () => Promise<void>;
  readonly logError?: (event: { requestId: string; errorName: string }) => void;
}

export function createPostgresLicenseApi(
  pool: Pool, auth: AccessTokenVerifier, licenses: PostgresLicenseService,
  publishing?: { auth: AccessTokenVerifier; publisher: PostgresAssetPublisher },
  packageReader?: PostgresPackageReader,
  isDraining: () => boolean = () => false,
  commerce?: PostgresCommerceService,
  administration?: { auth: AccessTokenVerifier; service: PostgresAdministrationService },
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
      operation === 'license-issue' ? 30 : operation === 'asset-publish' ? 3 : operation === 'asset-fetch' ? 60 : 10),
    issueChallenge: (tenantId, userId, deviceId) => issueDeviceChallenge(pool, tenantId, userId, deviceId),
    issueEnrollmentChallenge: (tenantId, userId, publicKeyPem, deviceClass) => issueDeviceEnrollmentChallenge(pool, tenantId, userId, publicKeyPem, deviceClass),
    registerDevice: (input) => registerDevice(pool, input),
    revokeDevice: (tenantId, userId, deviceId) => revokeOwnedDevice(pool, tenantId, userId, deviceId),
    licenses,
    ...(publishing ? { publishAuth: publishing.auth, publisher: publishing.publisher } : {}),
    ...(packageReader ? { packageReader } : {}),
    ...(packageReader && publishing ? { catalog: new PostgresCatalog(pool) } : {}),
    ...(commerce ? { commerce } : {}),
    ...(administration ? { adminAuth: administration.auth, administration: administration.service } : {}),
    ready: async () => {
      if (isDraining()) throw new DomainError('NOT_READY', 'API is draining');
      await pool.query('SELECT 1');
    },
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

async function readRawJson(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
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
  return Buffer.concat(chunks);
}

async function readJson(request: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<Record<string, unknown>> {
  const bytes = await readRawJson(request, maxBytes);
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
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
      encoded.length % 4 !== 0) {
    throw new DomainError('INVALID_REQUEST', 'Valid bounded base64 asset content required');
  }
  let padding = 0;
  if (encoded.endsWith('==')) padding = 2;
  else if (encoded.endsWith('=')) padding = 1;
  for (let index = 0; index < encoded.length; index++) {
    const char = encoded.charCodeAt(index);
    if (index >= encoded.length - padding ? char !== 61 :
      !((char >= 65 && char <= 90) || (char >= 97 && char <= 122) ||
        (char >= 48 && char <= 57) || char === 43 || char === 47)) {
      throw new DomainError('INVALID_REQUEST', 'Valid bounded base64 asset content required');
    }
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

function offerBody(body: Record<string, unknown>): Omit<CreateOfferInput, 'tenantId' | 'creatorUserId' | 'idempotencyKey'> {
  exactFields(body, ['assetId', 'assetVersion', 'policyId', 'policyVersion', 'label', 'amountMinor', 'currency']);
  if (!Number.isSafeInteger(body.assetVersion) || !Number.isSafeInteger(body.policyVersion) ||
      !Number.isSafeInteger(body.amountMinor) || typeof body.label !== 'string' || typeof body.currency !== 'string') {
    throw new DomainError('INVALID_REQUEST', 'Invalid offer terms');
  }
  return { assetId: uuid(body.assetId), policyId: uuid(body.policyId), assetVersion: body.assetVersion as number,
    policyVersion: body.policyVersion as number, label: body.label, amountMinor: body.amountMinor as number, currency: body.currency };
}

function oneStringHeader(request: IncomingMessage, name: string): string {
  const count = request.rawHeaders.filter((_, index) => index % 2 === 0 && request.rawHeaders[index]?.toLowerCase() === name).length;
  const value = request.headers[name];
  if (count !== 1 || typeof value !== 'string') throw new DomainError('INVALID_REQUEST', `One ${name} header required`);
  return value;
}

function adminGrantBody(body: Record<string, unknown>): Omit<AdminGrantInput, 'tenantId' | 'actorId' | 'idempotencyKey'> {
  exactFields(body, ['userId', 'assetId', 'assetVersion', 'policyId', 'policyVersion', 'source', 'validUntil']);
  if (!Number.isSafeInteger(body.assetVersion) || !Number.isSafeInteger(body.policyVersion) ||
      !['free', 'organization', 'trial'].includes(String(body.source)) || body.validUntil !== null && typeof body.validUntil !== 'string') {
    throw new DomainError('INVALID_REQUEST', 'Invalid entitlement terms');
  }
  return { userId: uuid(body.userId), assetId: uuid(body.assetId), assetVersion: body.assetVersion as number,
    policyId: uuid(body.policyId), policyVersion: body.policyVersion as number, source: body.source as AdminGrantInput['source'],
    validUntil: body.validUntil as string | null };
}

function uuid(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new DomainError('INVALID_REQUEST', 'UUID field required');
  return value.toLowerCase();
}

function oneUuidHeader(request: IncomingMessage, name: string): string {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) count++;
  }
  const value = request.headers[name];
  if (count !== 1 || typeof value !== 'string') throw new DomainError('INVALID_REQUEST', `One ${name} header required`);
  return uuid(value);
}

function catalogPage(url: URL): { limit: number; cursor?: string } {
  for (const key of url.searchParams.keys()) {
    if (!['limit', 'cursor'].includes(key) || url.searchParams.getAll(key).length !== 1) {
      throw new DomainError('INVALID_REQUEST', 'Invalid catalog query');
    }
  }
  const rawLimit = url.searchParams.get('limit');
  const limit = rawLimit === null ? 20 : Number(rawLimit);
  if (rawLimit !== null && !/^[1-9]\d{0,2}$/.test(rawLimit) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new DomainError('INVALID_REQUEST', 'Catalog limit must be 1–100');
  }
  const rawCursor = url.searchParams.get('cursor');
  return { limit, ...(rawCursor === null ? {} : { cursor: uuid(rawCursor) }) };
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
  if (error.code === 'DATABASE_UNAVAILABLE') return 503;
  if (error.code === 'PUBLISH_UNCERTAIN') return 503;
  if (['PAYMENT_UNCERTAIN', 'PAYMENT_UNAVAILABLE', 'PAYMENTS_DISABLED', 'PAYMENT_MISMATCH'].includes(error.code)) return 503;
  if (error.code === 'PAYMENT_REVIEW_REQUIRED') return 409;
  if (['ORDER_NOT_FOUND', 'OFFER_NOT_FOUND'].includes(error.code)) return 404;
  if (error.code === 'ORDER_CAPACITY') return 429;
  if (['ACCOUNT_EXISTS', 'ACCOUNT_REVOKED', 'LAST_ADMIN'].includes(error.code)) return 409;
  if (['ACCOUNT_NOT_FOUND', 'ENTITLEMENT_NOT_FOUND'].includes(error.code)) return 404;
  if (error.code === 'IDEMPOTENCY_CONFLICT' || error.code === 'PUBLICATION_ABANDONED') return 409;
  if (error.code === 'PUBLICATION_NOT_FOUND') return 404;
  if (error.code === 'PUBLICATION_CAPACITY') return 429;
  if (error.code.startsWith('BAO_') || error.code.startsWith('KMS_') ||
      error.code === 'INVALID_BAO_KEY' || error.code === 'INVALID_BAO_CONFIG' ||
      error.code.startsWith('STORAGE_') || error.code.startsWith('INVALID_STORAGE_') ||
      error.code === 'INVALID_SIGNATURE') return 503;
  if (error.code === 'RATE_LIMITED' || error.code === 'CHALLENGE_LIMIT') return 429;
  if (error.code === 'INVALID_REQUEST') return 400;
  if (error.code.startsWith('INVALID_')) return 400;
  return 403;
}

function databaseUnavailable(error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('code' in error) || typeof error.code !== 'string') return false;
  return error.code.startsWith('08') || ['ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'ETIMEDOUT', '53300', '57P01', '57014'].includes(error.code);
}

export function createLicenseApiServer(dependencies: LicenseApiDependencies,
  limits: { maxInFlight: number; maxLargeTransfers: number } = { maxInFlight: 16, maxLargeTransfers: 2 }): Server {
  if (!Number.isSafeInteger(limits.maxInFlight) || limits.maxInFlight < 1 || limits.maxInFlight > 256 ||
      !Number.isSafeInteger(limits.maxLargeTransfers) || limits.maxLargeTransfers < 1 || limits.maxLargeTransfers > limits.maxInFlight) {
    throw new DomainError('INVALID_REQUEST', 'Invalid HTTP concurrency limits');
  }
  let inFlight = 0;
  let largeTransfers = 0;
  const server = createServer((request, response) => {
    const requestId = randomUUID();
    const largeTransfer = request.method === 'POST' && request.url === '/v1/assets' ||
      request.method === 'GET' && /^\/v1\/assets\/[^/]+\/renditions\/[^/]+\/package$/.test(request.url ?? '');
    if (inFlight >= limits.maxInFlight || largeTransfer && largeTransfers >= limits.maxLargeTransfers) {
      response.setHeader('Retry-After', '1');
      response.setHeader('Connection', 'close');
      sendJson(response, 503, { error: 'CAPACITY_EXCEEDED' }, requestId);
      return;
    }
    inFlight++;
    if (largeTransfer) largeTransfers++;
    let operationDone = false;
    let responseDone = false;
    let released = false;
    const release = () => {
      if (released || !operationDone || !responseDone) return;
      released = true;
      inFlight--;
      if (largeTransfer) largeTransfers--;
    };
    const completeResponse = () => { responseDone = true; release(); };
    response.once('finish', completeResponse);
    response.once('close', completeResponse);
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
      if (request.method === 'POST' && url.pathname === '/v1/webhooks/stripe' && !url.search && dependencies.commerce) {
        const signature = oneStringHeader(request, 'stripe-signature');
        const bytes = await readRawJson(request, 256 * 1024);
        await dependencies.commerce.acceptWebhook(bytes, signature);
        sendJson(response, 200, { received: true }, requestId);
        return;
      }
      const adminRoute = dependencies.administration && dependencies.adminAuth && url.pathname.startsWith('/v1/admin/');
      if (adminRoute) {
        const userStatus = request.method === 'POST' ? /^\/v1\/admin\/users\/([^/]+)\/status$/.exec(url.pathname) : null;
        const revokeGrant = request.method === 'DELETE' ? /^\/v1\/admin\/entitlements\/([^/]+)$/.exec(url.pathname) : null;
        const userCreate = request.method === 'POST' && url.pathname === '/v1/admin/users';
        const grantCreate = request.method === 'POST' && url.pathname === '/v1/admin/entitlements';
        if (url.search || !userStatus && !revokeGrant && !userCreate && !grantCreate) {
          sendJson(response, 404, { error: 'NOT_FOUND' }, requestId); return;
        }
        const principal = await dependencies.adminAuth!.verify(oneAuthorizationHeader(request));
        const actorId = await dependencies.resolveUser(principal.tenantId, principal.externalSubject);
        await dependencies.consumeRate(principal.tenantId, actorId, 'commerce-write');
        if (revokeGrant) {
          await dependencies.administration!.revokeGrant(principal.tenantId, actorId, uuid(revokeGrant[1]));
          response.writeHead(204, { 'Cache-Control': 'no-store', 'X-Request-Id': requestId }); response.end(); return;
        }
        const body = await readJson(request);
        if (userCreate) {
          exactFields(body, ['subject', 'roles']);
          if (typeof body.subject !== 'string' || !Array.isArray(body.roles) || body.roles.some((role) => typeof role !== 'string')) {
            throw new DomainError('INVALID_REQUEST', 'Account subject and roles required');
          }
          const created = await dependencies.administration!.provisionUser(principal.tenantId, actorId,
            oneUuidHeader(request, 'idempotency-key'), body.subject, body.roles);
          sendJson(response, 201, { ...created }, requestId);
        } else if (userStatus) {
          exactFields(body, ['status']);
          if (typeof body.status !== 'string') throw new DomainError('INVALID_REQUEST', 'Account status required');
          await dependencies.administration!.setUserStatus(principal.tenantId, actorId, uuid(userStatus[1]), body.status);
          sendJson(response, 200, { changed: true }, requestId);
        } else {
          const granted = await dependencies.administration!.grant({ tenantId: principal.tenantId, actorId,
            idempotencyKey: oneUuidHeader(request, 'idempotency-key'), ...adminGrantBody(body) });
          sendJson(response, 201, { ...granted }, requestId);
        }
        return;
      }
      const revokeMatch = request.method === 'DELETE' ? /^\/v1\/devices\/([^/]+)$/.exec(url.pathname) : null;
      const packageMatch = request.method === 'GET' && dependencies.packageReader
        ? /^\/v1\/assets\/([^/]+)\/renditions\/([^/]+)\/package$/.exec(url.pathname) : null;
      const postRoute = request.method === 'POST' && [
        '/v1/device-enrollment-challenges', '/v1/devices', '/v1/device-challenges', '/v1/licenses',
      ].includes(url.pathname);
      const publishRoute = request.method === 'POST' && url.pathname === '/v1/assets' &&
        dependencies.publishAuth !== undefined && dependencies.publisher !== undefined;
      const publicationStatus = request.method === 'GET' && dependencies.publisher && dependencies.publishAuth
        ? /^\/v1\/publication-operations\/([^/]+)$/.exec(url.pathname) : null;
      const ownedCatalog = request.method === 'GET' && url.pathname === '/v1/creator/assets' &&
        dependencies.catalog && dependencies.publishAuth;
      const libraryCatalog = request.method === 'GET' && url.pathname === '/v1/library' && dependencies.catalog;
      const offersList = request.method === 'GET' && url.pathname === '/v1/offers' && dependencies.commerce;
      const offerCreate = request.method === 'POST' && url.pathname === '/v1/offers' && dependencies.commerce && dependencies.publishAuth;
      const offerDisable = request.method === 'DELETE' && dependencies.commerce && dependencies.publishAuth ? /^\/v1\/offers\/([^/]+)$/.exec(url.pathname) : null;
      const orderCreate = request.method === 'POST' && url.pathname === '/v1/orders' && dependencies.commerce;
      const orderStatus = request.method === 'GET' && dependencies.commerce ? /^\/v1\/orders\/([^/]+)$/.exec(url.pathname) : null;
      const orderReconcile = request.method === 'POST' && dependencies.commerce ? /^\/v1\/orders\/([^/]+)\/reconcile$/.exec(url.pathname) : null;
      if ((!ownedCatalog && !libraryCatalog && !offersList && url.search) ||
          (!postRoute && !revokeMatch && !publishRoute && !packageMatch && !publicationStatus && !ownedCatalog && !libraryCatalog &&
            !offersList && !offerCreate && !offerDisable && !orderCreate && !orderStatus && !orderReconcile)) {
        sendJson(response, 404, { error: 'NOT_FOUND' }, requestId);
        return;
      }
      const principal = await (publishRoute || publicationStatus || ownedCatalog || offerCreate || offerDisable ? dependencies.publishAuth! : dependencies.auth).verify(oneAuthorizationHeader(request));
      const userId = await dependencies.resolveUser(principal.tenantId, principal.externalSubject);
      if (offersList) {
        const page = catalogPage(url);
        await dependencies.consumeRate(principal.tenantId, userId, 'asset-fetch');
        sendJson(response, 200, { ...await dependencies.commerce!.listOffers(principal.tenantId, page.limit, page.cursor) }, requestId);
        return;
      }
      if (orderStatus) {
        await dependencies.consumeRate(principal.tenantId, userId, 'asset-fetch');
        sendJson(response, 200, { order: await dependencies.commerce!.order(principal.tenantId, userId, uuid(orderStatus[1])) }, requestId);
        return;
      }
      if (offerDisable) {
        await dependencies.consumeRate(principal.tenantId, userId, 'commerce-write');
        await dependencies.commerce!.disableOffer(principal.tenantId, userId, uuid(offerDisable[1]));
        response.writeHead(204, { 'Cache-Control': 'no-store', 'X-Request-Id': requestId });
        response.end();
        return;
      }
      if (offerCreate || orderCreate || orderReconcile) {
        await dependencies.consumeRate(principal.tenantId, userId, 'commerce-write');
        const body = await readJson(request);
        if (offerCreate) {
          const offer = await dependencies.commerce!.createOffer({ tenantId: principal.tenantId, creatorUserId: userId,
            idempotencyKey: oneUuidHeader(request, 'idempotency-key'), ...offerBody(body) });
          sendJson(response, 201, { ...offer }, requestId);
        } else if (orderCreate) {
          exactFields(body, ['offerId']);
          const order = await dependencies.commerce!.createOrder(principal.tenantId, userId, uuid(body.offerId), oneUuidHeader(request, 'idempotency-key'));
          sendJson(response, 201, { ...await dependencies.commerce!.checkout(principal.tenantId, userId, order.orderId) }, requestId);
        } else {
          exactFields(body, []);
          sendJson(response, 200, { order: await dependencies.commerce!.reconcileOrder(principal.tenantId, userId, uuid(orderReconcile![1])) }, requestId);
        }
        return;
      }
      if (ownedCatalog || libraryCatalog) {
        const page = catalogPage(url);
        await dependencies.consumeRate(principal.tenantId, userId, 'asset-fetch');
        const result = ownedCatalog
          ? await dependencies.catalog!.owned(principal.tenantId, userId, page.limit, page.cursor)
          : await dependencies.catalog!.library(principal.tenantId, userId, page.limit, page.cursor);
        sendJson(response, 200, { ...result }, requestId);
        return;
      }
      if (publicationStatus) {
        const operation = await dependencies.publisher!.status(principal.tenantId, userId, uuid(publicationStatus[1]));
        sendJson(response, 200, { operation }, requestId);
        return;
      }
      if (publishRoute) await dependencies.consumeRate(principal.tenantId, userId, 'asset-publish');
      if (packageMatch) {
        await dependencies.consumeRate(principal.tenantId, userId, 'asset-fetch');
        const bytes = await dependencies.packageReader!.read({
          tenantId: principal.tenantId, authenticatedUserId: userId,
          assetId: uuid(packageMatch[1]), renditionId: uuid(packageMatch[2]),
          licenseId: oneUuidHeader(request, 'x-drm-license-id'),
        });
        response.writeHead(200, {
          'Content-Type': 'application/vnd.drm.secure-package+json',
          'Content-Length': bytes.length,
          'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
          'X-Request-Id': requestId,
        });
        response.end(bytes);
        return;
      }
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
        try {
          const idempotencyKey = oneUuidHeader(request, 'idempotency-key');
          const published = await dependencies.publisher!.publish({ tenantId: principal.tenantId, ownerUserId: userId, idempotencyKey, ...input });
          sendJson(response, 201, { asset: published }, requestId);
        } finally {
          input.content.fill(0);
        }
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
      if (databaseUnavailable(error)) {
        response.setHeader('Retry-After', '1');
        sendJson(response, 503, { error: 'DATABASE_UNAVAILABLE' }, requestId);
      } else sendJson(response, 500, { error: 'INTERNAL_ERROR' }, requestId);
    }).finally(() => { operationDone = true; release(); });
  });
  server.maxConnections = 256;
  server.maxHeadersCount = 50;
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;
  return server;
}
