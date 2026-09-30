import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const directory = fileURLToPath(new URL('../infrastructure/postgres/', import.meta.url));
const files = readdirSync(directory).filter((name) => /^\d{3}_[a-z0-9_]+\.sql$/.test(name)).sort();
if (files.length === 0) throw new Error('No migrations found');

const caFile = process.env.MIGRATION_DATABASE_CA_FILE;
const databaseUrl = process.env.MIGRATION_DATABASE_URL;
const localHost = (host: string) => host.startsWith('/') || ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host);
if (databaseUrl) {
  const endpoint = new URL(databaseUrl);
  if (!['postgres:', 'postgresql:'].includes(endpoint.protocol) || endpoint.search || endpoint.hash ||
      !localHost(endpoint.hostname) && !caFile) {
    throw new Error('Remote migration database requires a trusted CA file');
  }
} else if (!localHost(process.env.PGHOST ?? 'localhost') && !caFile) {
  throw new Error('Remote migration database requires a trusted CA file');
}
const client = new pg.Client({
  ...(databaseUrl ? { connectionString: databaseUrl } : {}),
  ...(caFile ? { ssl: { ca: readFileSync(caFile, 'utf8'), rejectUnauthorized: true } } : {}),
  connectionTimeoutMillis: 5000,
  query_timeout: 30_000,
});

async function main(): Promise<void> {
  await client.connect();
  try {
    await client.query('SELECT pg_advisory_lock(1735554652, 1146241357)');
    try {
      await client.query(`CREATE TABLE IF NOT EXISTS public.drm_schema_migrations (
        version text PRIMARY KEY,
        checksum_sha256 text NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
      )`);
      const applied = await client.query<{ version: string; checksum_sha256: string }>(
        'SELECT version, checksum_sha256 FROM public.drm_schema_migrations ORDER BY version');
      const known = new Map(applied.rows.map((row) => [row.version, row.checksum_sha256]));
      if (applied.rows.some((row, index) => files[index] !== row.version)) {
        throw new Error('Migration history is missing, reordered, or unknown');
      }
      if (applied.rows.length === 0) {
        const existing = await client.query<{ exists: string | null }>("SELECT to_regclass('drm.tenants')::text AS exists");
        if (existing.rows[0]?.exists) throw new Error('Existing DRM schema has no migration ledger; controlled baseline required');
      }
      for (const name of files) {
        const source = readFileSync(`${directory}/${name}`, 'utf8');
        const checksum = createHash('sha256').update(source).digest('hex');
        const recorded = known.get(name);
        if (recorded) {
          if (recorded !== checksum) throw new Error(`Migration checksum changed: ${name}`);
          continue;
        }
        const body = source.replace(/^BEGIN;\s*/u, '').replace(/\s*COMMIT;\s*$/u, '');
        if (body === source) throw new Error(`Migration must have transaction wrapper: ${name}`);
        await client.query('BEGIN');
        try {
          await client.query(body);
          await client.query('INSERT INTO public.drm_schema_migrations (version, checksum_sha256) VALUES ($1, $2)', [name, checksum]);
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK');
          throw error;
        }
        process.stdout.write(JSON.stringify({ event: 'migration.applied', version: name }) + '\n');
        known.set(name, checksum);
      }
    } finally {
      await client.query('SELECT pg_advisory_unlock(1735554652, 1146241357)');
    }
  } finally {
    await client.end();
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(JSON.stringify({ event: 'migration.failed', reason: error instanceof Error ? error.message : 'UnknownError' }) + '\n');
  process.exitCode = 1;
});
