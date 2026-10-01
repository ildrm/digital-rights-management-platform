import test from 'node:test';
import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createStandaloneArchive, extractStandaloneArchive, readBackupPassphrase, SECRET_PATHS } from '../lib/standalone-backup.ts';

test('standalone backup authenticates the entire dump and keys before exposing recovered files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'drm-backup-test-'));
  const secrets = join(directory, 'secrets'), archive = join(directory, 'backup.drmbackup');
  const passphrase = randomBytes(32);
  try {
    await mkdir(secrets); await mkdir(join(secrets, 'database')); await mkdir(join(secrets, 'keys'));
    for (const path of SECRET_PATHS) await writeFile(join(secrets, path), `secret-${path}`, { mode: 0o600 });
    const dump = Buffer.concat([Buffer.from('PGDMP'), randomBytes(100_000)]);
    async function* source(): AsyncGenerator<Buffer> { yield dump.subarray(0, 900); yield dump.subarray(900); }
    const report = await createStandaloneArchive(archive, secrets, passphrase, source());
    assert.ok(report.backupBytes > dump.length);
    assert.match(report.backupSha256, /^[a-f0-9]{64}$/);
    assert.equal((await lstat(archive)).mode & 0o077, 0);
    const recovered = join(directory, 'recovered');
    const extracted = await extractStandaloneArchive(archive, recovered, passphrase);
    assert.equal(extracted.recoveredSecrets, SECRET_PATHS.length);
    assert.deepEqual(await readFile(join(recovered, 'database.dump')), dump);
    for (const path of SECRET_PATHS) {
      assert.deepEqual(await readFile(join(recovered, path)), await readFile(join(secrets, path)));
      assert.equal((await lstat(join(recovered, path))).mode & 0o077, 0);
    }
    await assert.rejects(createStandaloneArchive(archive, secrets, passphrase, source()), { code: 'EEXIST' });
    await assert.rejects(extractStandaloneArchive(archive, recovered, passphrase), { code: 'EEXIST' });
    assert.deepEqual(await readFile(join(recovered, 'database.dump')), dump, 'Existing recovery was modified');
    const wrongDestination = join(directory, 'wrong-key');
    await assert.rejects(extractStandaloneArchive(archive, wrongDestination, randomBytes(32)));
    await assert.rejects(lstat(wrongDestination), { code: 'ENOENT' });
    const corrupted = await readFile(archive); corrupted[corrupted.length - 100]! ^= 1;
    await writeFile(join(directory, 'corrupt'), corrupted);
    const invalidDestination = join(directory, 'corrupt-recovery');
    await assert.rejects(extractStandaloneArchive(join(directory, 'corrupt'), invalidDestination, passphrase));
    await assert.rejects(lstat(invalidDestination), { code: 'ENOENT' });
    async function* failedDump(): AsyncGenerator<Buffer> { yield Buffer.from('PGDMP'); throw new Error('database disconnected'); }
    const failedArchive = join(directory, 'failed');
    await assert.rejects(createStandaloneArchive(failedArchive, secrets, passphrase, failedDump()));
    await assert.rejects(lstat(failedArchive), { code: 'ENOENT' });
    const passphraseFile = join(directory, 'passphrase');
    await writeFile(passphraseFile, 'x'.repeat(32), { mode: 0o600 });
    assert.equal((await readBackupPassphrase(passphraseFile)).length, 32);
    await writeFile(passphraseFile, 'short');
    await assert.rejects(readBackupPassphrase(passphraseFile));
  } finally { passphrase.fill(0); await rm(directory, { recursive: true, force: true }); }
});
