import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createStandaloneArchive, extractStandaloneArchive, readBackupPassphrase } from './lib/standalone-backup.ts';

async function main(): Promise<void> {
  const [command, file, directory] = process.argv.slice(2);
  const passphrasePath = process.env.BACKUP_PASSPHRASE_FILE;
  if (!['create', 'extract'].includes(command ?? '') || !file || !directory || !passphrasePath) {
    throw new Error('Usage: BACKUP_PASSPHRASE_FILE=<private-file> standalone-backup.ts create <new-backup-file> <secret-directory> | extract <backup-file> <new-recovery-directory>');
  }
  const passphrase = await readBackupPassphrase(passphrasePath);
  try {
    if (command === 'extract') {
      const report = await extractStandaloneArchive(file, directory, passphrase);
      process.stdout.write(JSON.stringify({ event: 'backup.extracted', ...report }) + '\n');
      return;
    }
    // Refuse a mismatched secret snapshot and Compose mount configuration.
    const configured = resolve(process.env.DRM_SECRET_DIR ?? '.secrets/standalone');
    if (configured !== resolve(directory)) throw new Error('DRM_SECRET_DIR must match the secret directory being backed up');
    const direct = process.env.BACKUP_DATABASE_URL;
    let executable = 'docker';
    const composeProject = process.env.COMPOSE_PROJECT_NAME;
    let args = ['compose', '-f', 'compose.standalone.yaml', ...(composeProject ? ['-p', composeProject] : []),
      'exec', '-T', 'postgres', 'pg_dump', '-U', 'postgres', '-d', 'drm', '--format=custom', '--no-owner', '--no-acl'];
    let environment = process.env;
    if (direct) {
      const url = new URL(direct);
      if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname || !url.username || url.password || url.search || url.hash || url.pathname.length < 2) {
        throw new Error('BACKUP_DATABASE_URL must have no password or connection parameters');
      }
      executable = 'pg_dump';
      args = ['--format=custom', '--no-owner', '--no-acl', url.toString()];
      environment = { ...process.env, PGSSLMODE: 'verify-full', PGSSLROOTCERT: resolve(directory, 'database/ca.crt'),
        PGPASSWORD: (await readFile(resolve(directory, 'database/owner-password'), 'utf8')).trim() };
    }
    const child = spawn(executable, args, { stdio: ['ignore', 'pipe', 'pipe'], env: environment });
    const completed = new Promise<void>((success, failure) => {
      child.once('error', failure);
      child.once('close', (code) => code === 0 ? success() : failure(new Error('Docker PostgreSQL backup failed')));
    });
    completed.catch(() => undefined);
    child.stderr.resume();
    const timeout = setTimeout(() => child.kill('SIGKILL'), 30 * 60_000); timeout.unref();
    try {
      async function* dump(): AsyncGenerator<Buffer> {
        for await (const bytes of child.stdout) yield Buffer.from(bytes);
        await completed;
      }
      const report = await createStandaloneArchive(file, directory, passphrase, dump());
      process.stdout.write(JSON.stringify({ event: 'backup.created', ...report }) + '\n');
    } finally {
      clearTimeout(timeout); child.kill(); child.stdout.destroy();
      await completed.catch(() => undefined);
    }
  } finally { passphrase.fill(0); }
}
void main().catch(() => {
  process.stderr.write('Backup operation failed. Check paths, private passphrase, Docker state, and archive integrity. No credentials are printed.\n');
  process.exitCode = 1;
});
