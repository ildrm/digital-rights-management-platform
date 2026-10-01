import { readFileSync } from 'node:fs';
import { S3Client } from '@aws-sdk/client-s3';
import pg from 'pg';
import { S3CompatiblePackageStore } from '@drm/aws-s3';
import { OpenBaoKeyWrapper, OpenBaoLicenseSigner, OpenBaoTransitClient, type TenantTransitKeyRing } from '@drm/openbao';
import { PostgresAssetPublisher, PostgresLicenseService, PostgresPackageReader, PostgresPackageStore, type ProtectedPackageStore } from '@drm/postgres';
import { createPostgresLicenseApi, LocalAccessTokenVerifier, OidcAccessTokenVerifier } from './index.ts';
import { LocalKeyWrapper, LocalLicenseSigner } from './local-keys.ts';
import { armHardStop, endPoolWithin } from './runtime-deadlines.ts';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
}

function tenantKeyMap(input: string): ReadonlyMap<string, TenantTransitKeyRing> {
  const parsed: unknown = JSON.parse(input);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('OPENBAO_TENANT_KEYS_JSON must be an object');
  const entries = Object.entries(parsed);
  if (entries.length === 0) throw new Error('At least one tenant OpenBao key is required');
  const map = new Map<string, TenantTransitKeyRing>();
  const validName = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(value);
  for (const [tenantId, value] of entries) {
    const ring = value as Record<string, unknown>;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId) ||
        !ring || typeof ring !== 'object' || Array.isArray(ring) ||
        Object.keys(ring).length !== 2 || !Object.hasOwn(ring, 'activeKeyName') || !Object.hasOwn(ring, 'permittedKeyNames') ||
        !validName(ring.activeKeyName) || !Array.isArray(ring.permittedKeyNames) || ring.permittedKeyNames.length < 1 ||
        !ring.permittedKeyNames.every(validName) || !ring.permittedKeyNames.includes(ring.activeKeyName) ||
        new Set(ring.permittedKeyNames).size !== ring.permittedKeyNames.length) {
      throw new Error('OPENBAO_TENANT_KEYS_JSON contains an invalid tenant or key name');
    }
    map.set(tenantId.toLowerCase(), { activeKeyName: ring.activeKeyName, permittedKeyNames: ring.permittedKeyNames });
  }
  return map;
}

async function main(): Promise<void> {
  const databaseUrl = new URL(required('DATABASE_URL'));
  if (!['postgres:', 'postgresql:'].includes(databaseUrl.protocol) || !databaseUrl.hostname || databaseUrl.search) {
    throw new Error('DATABASE_URL must be a PostgreSQL URL without connection parameters');
  }
  const ca = readFileSync(required('DATABASE_CA_FILE'), 'utf8');
  const databasePassword = process.env.DATABASE_PASSWORD_FILE ? readFileSync(required('DATABASE_PASSWORD_FILE'), 'utf8').trim() : undefined;
  if (databasePassword) databaseUrl.password = databasePassword;
  const portText = process.env.PORT ?? '8080';
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1–65535');
  const host = process.env.LISTEN_HOST ?? '127.0.0.1';
  const pool = new pg.Pool({
    connectionString: databaseUrl.toString(),
    ssl: { ca, rejectUnauthorized: true },
    max: 10, connectionTimeoutMillis: 3000, idleTimeoutMillis: 30_000,
    query_timeout: 12_000,
  });
  pool.on('error', (error) => {
    process.stderr.write(JSON.stringify({ event: 'database.idle_client_error', errorName: error.name }) + '\n');
  });
  const keyProvider = process.env.KEY_PROVIDER ?? 'openbao';
  let signer: OpenBaoLicenseSigner | LocalLicenseSigner;
  let wrapper: OpenBaoKeyWrapper | LocalKeyWrapper;
  if (keyProvider === 'local') {
    const wrappingKeyText = readFileSync(required('LOCAL_WRAPPING_KEY_FILE'), 'utf8').trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(wrappingKeyText)) throw new Error('LOCAL_WRAPPING_KEY_FILE must contain 32 base64url bytes');
    const wrappingKey = Buffer.from(wrappingKeyText, 'base64url');
    if (wrappingKey.length !== 32 || wrappingKey.toString('base64url') !== wrappingKeyText) throw new Error('Invalid local wrapping key');
    wrapper = new LocalKeyWrapper(wrappingKey, required('LOCAL_KEY_VERSION'));
    wrappingKey.fill(0);
    signer = new LocalLicenseSigner(readFileSync(required('LOCAL_SIGNING_KEY_FILE'), 'utf8'), required('LOCAL_KEY_VERSION'));
  } else if (keyProvider === 'openbao') {
    const keyMap = tenantKeyMap(required('OPENBAO_TENANT_KEYS_JSON'));
    const bao = new OpenBaoTransitClient(required('OPENBAO_ADDR'), readFileSync(required('OPENBAO_TOKEN_FILE'), 'utf8').trim());
    signer = new OpenBaoLicenseSigner(bao, required('OPENBAO_SIGNING_KEY_NAME'), Number(required('OPENBAO_SIGNING_KEY_VERSION')));
    wrapper = new OpenBaoKeyWrapper(bao, (tenantId) => keyMap.get(tenantId.toLowerCase()) ?? { activeKeyName: '', permittedKeyNames: [] });
  } else throw new Error('KEY_PROVIDER must be local or openbao');
  const authProvider = process.env.AUTH_PROVIDER ?? 'oidc';
  const makeAuth = (requiredScope: string) => {
    if (authProvider === 'local') return new LocalAccessTokenVerifier(
      readFileSync(required('LOCAL_AUTH_PUBLIC_KEY_FILE'), 'utf8'), required('LOCAL_AUTH_ISSUER'), required('LOCAL_AUTH_AUDIENCE'), requiredScope);
    if (authProvider === 'oidc') return new OidcAccessTokenVerifier({
      issuer: required('OIDC_ISSUER'), audience: required('OIDC_AUDIENCE'),
      jwksUrl: required('OIDC_JWKS_URL'), requiredScope,
    });
    throw new Error('AUTH_PROVIDER must be local or oidc');
  };
  const auth = makeAuth('drm:license');
  const licenses = new PostgresLicenseService(pool, signer, wrapper, required('LICENSE_ISSUER'), () => new Date().toISOString());
  const bucket = process.env.PACKAGE_BUCKET;
  const objectEndpoint = process.env.OBJECT_STORE_ENDPOINT;
  const storageMode = process.env.PACKAGE_STORE ?? (bucket || objectEndpoint ? 's3' : 'none');
  if (!['none', 'postgres', 's3'].includes(storageMode) ||
      storageMode === 'postgres' && (bucket || objectEndpoint) ||
      storageMode === 's3' && (!bucket || !objectEndpoint) ||
      storageMode === 'none' && (bucket || objectEndpoint)) {
    throw new Error('PACKAGE_STORE must be none, postgres, or s3 with matching object-store settings');
  }
  let s3: S3Client | undefined;
  let store: ProtectedPackageStore | undefined;
  if (storageMode === 'postgres') store = new PostgresPackageStore(pool);
  if (storageMode === 's3' && bucket && objectEndpoint) {
    const endpoint = new URL(objectEndpoint);
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/') {
      throw new Error('OBJECT_STORE_ENDPOINT must be an HTTPS origin');
    }
    s3 = new S3Client({
      region: process.env.OBJECT_STORE_REGION ?? 'us-east-1', endpoint: endpoint.toString(), forcePathStyle: true,
      credentials: {
        accessKeyId: readFileSync(required('OBJECT_STORE_ACCESS_KEY_FILE'), 'utf8').trim(),
        secretAccessKey: readFileSync(required('OBJECT_STORE_SECRET_KEY_FILE'), 'utf8').trim(),
      },
      maxAttempts: 3,
    });
    store = new S3CompatiblePackageStore(s3, bucket);
  }
  const publishing = store ? {
    auth: makeAuth('drm:publish'),
    publisher: new PostgresAssetPublisher(pool, store, wrapper, signer),
  } : undefined;
  let shuttingDown = false;
  const server = createPostgresLicenseApi(pool, auth, licenses, publishing,
    store ? new PostgresPackageReader(pool, store) : undefined, () => shuttingDown);
  try {
    await pool.query('SELECT 1');
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        server.off('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(port, host);
    });
    process.stdout.write(JSON.stringify({ event: 'api.started', host, port }) + '\n');
  } catch (error) {
    s3?.destroy();
    await endPoolWithin(pool);
    throw error;
  }
  let maintenanceRun: Promise<void> | undefined;
  let tenantCursor = '00000000-0000-0000-0000-000000000000';
  const reconcile = () => {
    if (shuttingDown || maintenanceRun || !publishing) return;
    maintenanceRun = (async () => {
      const tenants = await pool.query<{ id: string }>('SELECT id FROM drm.tenants WHERE id > $1 ORDER BY id LIMIT 4', [tenantCursor]);
      tenantCursor = tenants.rows.at(-1)?.id ?? '00000000-0000-0000-0000-000000000000';
      const results = await Promise.allSettled(tenants.rows.map(async ({ id }) => {
        const result = await publishing.publisher.reconcile(id, 2);
        if (result.recovered || result.pending || result.cleaned) process.stdout.write(JSON.stringify({ event: 'publication.reconciled', tenantId: id, ...result }) + '\n');
      }));
      for (const result of results) if (result.status === 'rejected') {
        process.stderr.write(JSON.stringify({ event: 'publication.reconciliation_failed', errorName: result.reason instanceof Error ? result.reason.name : 'UnknownError' }) + '\n');
      }
    })().catch((error: unknown) => {
      process.stderr.write(JSON.stringify({ event: 'publication.discovery_failed', errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
    }).finally(() => { maintenanceRun = undefined; });
  };
  const maintenanceTimer = setInterval(reconcile, 5000);
  maintenanceTimer.unref();
  reconcile();
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    clearInterval(maintenanceTimer);
    armHardStop();
    const force = setTimeout(() => server.closeAllConnections(), 10_000);
    force.unref();
    try {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await maintenanceRun;
      await endPoolWithin(pool);
      s3?.destroy();
      process.stdout.write(JSON.stringify({ event: 'api.stopped' }) + '\n');
    } catch (error) {
      process.stderr.write(JSON.stringify({ event: 'api.shutdown_failed', errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
      process.exitCode = 1;
    } finally {
      clearTimeout(force);
    }
  };
  process.once('SIGTERM', () => { void shutdown(); });
  process.once('SIGINT', () => { void shutdown(); });
}

void main().catch((error: unknown) => {
  process.stderr.write(JSON.stringify({ event: 'api.start_failed', errorName: error instanceof Error ? error.name : 'UnknownError' }) + '\n');
  process.exitCode = 1;
});
