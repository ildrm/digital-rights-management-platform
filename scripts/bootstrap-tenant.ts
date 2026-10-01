import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import pg from 'pg';

const [slug, subject] = process.argv.slice(2);
if (!slug || !/^[a-z][a-z0-9-]{2,79}$/.test(slug) || !subject || subject.length > 256) {
  throw new Error('Usage: bootstrap-tenant.ts <lowercase-tenant-slug> <operator-subject>');
}
const file = (name: string) => readFileSync(process.env[name] ?? (() => { throw new Error(`Missing ${name}`); })(), 'utf8').trim();
const databaseUrl = new URL(process.env.MIGRATION_DATABASE_URL ?? (() => { throw new Error('Missing MIGRATION_DATABASE_URL'); })());
databaseUrl.password = file('MIGRATION_DATABASE_PASSWORD_FILE');
const client = new pg.Client({
  connectionString: databaseUrl.toString(),
  ssl: { ca: file('MIGRATION_DATABASE_CA_FILE'), rejectUnauthorized: true },
});
await client.connect();
try {
  await client.query('BEGIN');
  const tenantId = randomUUID();
  const userId = randomUUID();
  await client.query('INSERT INTO drm.tenants(id, slug) VALUES ($1, $2)', [tenantId, slug]);
  await client.query('INSERT INTO drm.users(tenant_id, id, external_subject, status) VALUES ($1, $2, $3, $4)', [tenantId, userId, subject, 'active']);
  for (const role of ['admin', 'creator', 'customer']) await client.query('INSERT INTO drm.user_roles(tenant_id,user_id,role) VALUES ($1,$2,$3)', [tenantId, userId, role]);
  await client.query('COMMIT');
  process.stdout.write(JSON.stringify({ tenantId, userId, subject }) + '\n');
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  await client.end();
}
