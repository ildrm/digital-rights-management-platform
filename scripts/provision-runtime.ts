import { readFileSync } from 'node:fs';
import pg from 'pg';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
}

const apiPassword = readFileSync(required('API_DATABASE_PASSWORD_FILE'), 'utf8').trim();
const workerPassword = readFileSync(required('WORKER_DATABASE_PASSWORD_FILE'), 'utf8').trim();
if (apiPassword.length < 32 || workerPassword.length < 32 || apiPassword === workerPassword) throw new Error('Distinct 32-character database passwords required');
const databaseUrl = new URL(required('MIGRATION_DATABASE_URL'));
databaseUrl.password = readFileSync(required('MIGRATION_DATABASE_PASSWORD_FILE'), 'utf8').trim();
const client = new pg.Client({
  connectionString: databaseUrl.toString(),
  ssl: { ca: readFileSync(required('MIGRATION_DATABASE_CA_FILE'), 'utf8'), rejectUnauthorized: true },
  connectionTimeoutMillis: 5000,
});
try {
  await client.connect();
  await client.query(readFileSync(new URL('../infrastructure/postgres/provision-runtime.sql', import.meta.url), 'utf8'));
  for (const [login, role, password] of [
    ['drm_api', 'drm_runtime_api', apiPassword],
    ['drm_worker', 'drm_runtime_worker', workerPassword],
  ]) {
    const existing = await client.query<{ exists: boolean }>('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1) AS exists', [login]);
    if (!existing.rows[0]?.exists) await client.query(`CREATE ROLE ${login} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
    const flags = await client.query<{ unsafe: boolean }>(
      'SELECT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR NOT rolcanlogin) AS unsafe FROM pg_roles WHERE rolname = $1', [login]);
    if (flags.rows[0]?.unsafe) throw new Error(`Unsafe existing login: ${login}`);
    const safe = await client.query<{ sql: string }>('SELECT format($1, $2::text, $3::text) AS sql', ['ALTER ROLE %I PASSWORD %L', login, password]);
    await client.query(safe.rows[0]!.sql);
    await client.query(`GRANT ${role} TO ${login}`);
  }
  process.stdout.write('Runtime database roles provisioned.\n');
} finally {
  await client.end();
}
