import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import pg from 'pg';

const run = promisify(execFile);

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function databaseUrl(name: string): URL {
  const url = new URL(required(name));
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname ||
      url.username === '' || url.password || url.search || url.hash || url.pathname.length < 2) {
    throw new Error(`${name} must be a PostgreSQL URL without an embedded password or parameters`);
  }
  return url;
}

async function fingerprint(client: pg.PoolClient): Promise<Record<string, { rows: string; digest: string }>> {
  const role = await client.query<{ allowed: boolean }>(
    'SELECT rolsuper OR rolbypassrls AS allowed FROM pg_roles WHERE rolname = current_user');
  if (!role.rows[0]?.allowed) throw new Error('The drill requires a backup role that can read all tenant rows');
  const tables = await client.query<{ tablename: string }>(
    "SELECT tablename FROM pg_tables WHERE schemaname = 'drm' ORDER BY tablename");
  if (!tables.rows.length) throw new Error('No drm tables found');
  const output: Record<string, { rows: string; digest: string }> = {};
  for (const { tablename } of tables.rows) {
    if (!/^[a-z][a-z0-9_]*$/.test(tablename)) throw new Error('Unexpected table name');
    const result = await client.query<{ rows: string; digest: string }>(
      `SELECT count(*)::text AS rows,
        md5(coalesce(string_agg(md5(to_jsonb(t)::text), '' ORDER BY md5(to_jsonb(t)::text)), '')) AS digest
        FROM drm.${tablename} t`);
    output[tablename] = result.rows[0]!;
  }
  return output;
}

async function main(): Promise<void> {
  const source = databaseUrl('DR_SOURCE_URL');
  const admin = databaseUrl('DR_TARGET_ADMIN_URL');
  const targetName = required('DR_TARGET_NAME');
  if (!/^drm_restore_[a-z0-9_]{1,40}$/.test(targetName) ||
      decodeURIComponent(source.pathname.slice(1)) === targetName) {
    throw new Error('DR_TARGET_NAME must be a distinct drm_restore_* database');
  }
  const ca = process.env.DR_DATABASE_CA_FILE ? await readFile(process.env.DR_DATABASE_CA_FILE, 'utf8') : undefined;
  const remote = [source.hostname, admin.hostname].some((host) => !['localhost', '127.0.0.1', '[::1]'].includes(host));
  if (remote && !ca) throw new Error('DR_DATABASE_CA_FILE is required for remote databases');
  const childEnvironment = ca ? { ...process.env, PGSSLMODE: 'verify-full',
    PGSSLROOTCERT: process.env.DR_DATABASE_CA_FILE! } : process.env;
  const connection = (url: URL) => ({ connectionString: url.toString(), max: 1,
    ...(ca ? { ssl: { ca, rejectUnauthorized: true } } : {}) });
  const sourcePool = new pg.Pool(connection(source));
  const adminPool = new pg.Pool(connection(admin));
  const target = new URL(admin);
  target.pathname = `/${targetName}`;
  const targetPool = new pg.Pool(connection(target));
  const directory = await mkdtemp(join(tmpdir(), 'drm-restore-'));
  const backup = join(directory, 'backup.dump');
  let created = false;
  try {
    const sourceClient = await sourcePool.connect();
    let sourceFingerprint: Awaited<ReturnType<typeof fingerprint>>;
    const backupStart = performance.now();
    try {
      await sourceClient.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const snapshot = await sourceClient.query<{ id: string }>('SELECT pg_export_snapshot() AS id');
      sourceFingerprint = await fingerprint(sourceClient);
      await run('pg_dump', ['--format=custom', '--no-owner', '--no-acl', `--snapshot=${snapshot.rows[0]!.id}`,
        '--file', backup, source.toString()], { env: childEnvironment, timeout: 3_600_000, maxBuffer: 1024 * 1024 });
      await sourceClient.query('COMMIT');
    } catch (error) {
      await sourceClient.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      sourceClient.release();
    }
    const backupSeconds = (performance.now() - backupStart) / 1000;
    // CREATE DATABASE cannot run in a transaction. The restrictive target name
    // and create-only behavior prevent overwriting an existing database.
    await adminPool.query(`CREATE DATABASE "${targetName}"`);
    created = true;
    const restoreStart = performance.now();
    await run('pg_restore', ['--exit-on-error', '--single-transaction', '--no-owner', '--no-acl',
      '--dbname', target.toString(), backup], { env: childEnvironment, timeout: 3_600_000, maxBuffer: 1024 * 1024 });
    const restoreSeconds = (performance.now() - restoreStart) / 1000;
    const targetClient = await targetPool.connect();
    let targetFingerprint: Awaited<ReturnType<typeof fingerprint>>;
    try { targetFingerprint = await fingerprint(targetClient); }
    finally { targetClient.release(); }
    const matched = JSON.stringify(sourceFingerprint) === JSON.stringify(targetFingerprint);
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(backup)) hash.update(chunk);
    const backupBytes = (await stat(backup)).size;
    const report = {
      recordedAt: new Date().toISOString(), targetDatabase: targetName,
      backupSha256: hash.digest('hex'), backupBytes,
      tableCount: Object.keys(sourceFingerprint).length, backupSeconds, restoreSeconds,
      dataMatched: matched, rpoSeconds: null, fullRtoSeconds: null,
      scope: 'PostgreSQL snapshot restore only; signing/wrapping keys, external stores, and endpoint failover require separate drills',
    };
    const output = `${JSON.stringify(report, null, 2)}\n`;
    if (process.env.DR_REPORT_FILE) await writeFile(process.env.DR_REPORT_FILE, output, { flag: 'wx', mode: 0o600 });
    process.stdout.write(output);
    if (!matched) process.exitCode = 1;
  } finally {
    await sourcePool.end();
    await targetPool.end();
    if (created && process.env.DR_KEEP_TARGET !== '1') {
      await adminPool.query(`DROP DATABASE "${targetName}" WITH (FORCE)`);
    }
    await adminPool.end();
    await rm(directory, { recursive: true, force: true });
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Restore drill failed'}\n`);
  process.exitCode = 2;
});
