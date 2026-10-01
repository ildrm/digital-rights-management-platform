import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import pg from 'pg';

const [tenantId, subject] = process.argv.slice(2);
if (!tenantId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId) || !subject || subject.length > 256) {
  throw new Error('Usage: bootstrap-admin-role.ts <tenant-uuid> <existing-active-subject>');
}
function secret(name: string): string {
  const file = process.env[name]; if (!file) throw new Error(`Missing ${name}`);
  return readFileSync(file, 'utf8').trim();
}
const url = new URL(process.env.MIGRATION_DATABASE_URL ?? (() => { throw new Error('Missing MIGRATION_DATABASE_URL'); })());
url.password = secret('MIGRATION_DATABASE_PASSWORD_FILE');
const client = new pg.Client({ connectionString: url.toString(), ssl: { ca: secret('MIGRATION_DATABASE_CA_FILE'), rejectUnauthorized: true } });
await client.connect();
try {
  await client.query('BEGIN');
  const user = await client.query<{ id: string }>("SELECT id FROM drm.users WHERE tenant_id = $1 AND external_subject = $2 AND status = 'active' FOR UPDATE", [tenantId, subject]);
  if (!user.rows[0]) throw new Error('Active account not found in the specified tenant');
  const inserted = await client.query("INSERT INTO drm.user_roles(tenant_id,user_id,role) VALUES ($1,$2,'admin') ON CONFLICT DO NOTHING RETURNING user_id", [tenantId, user.rows[0].id]);
  if (inserted.rowCount) await client.query(`INSERT INTO drm.audit_events(tenant_id,id,event_type,details)
    VALUES ($1,$2,'identity.admin_bootstrapped',$3)`, [tenantId, randomUUID(), { userId: user.rows[0].id }]);
  await client.query('COMMIT');
  process.stdout.write('Administrator role provisioned for the existing tenant account.\n');
} catch (error) { await client.query('ROLLBACK'); throw error; }
finally { await client.end(); }
