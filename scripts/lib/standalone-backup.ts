import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { appendFile, link, lstat, mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const MAGIC = Buffer.from('DRMBACKUP1\n');
const HEADER_BYTES = MAGIC.length + 16 + 12;
const MAX_METADATA = 2 * 1024 * 1024;
const MAX_ARCHIVE = 1024 ** 4;
export const SECRET_PATHS = [
  'database/owner-password', 'database/api-password', 'database/worker-password',
  'database/ca.crt', 'database/ca.key', 'database/server.crt', 'database/server.key',
  'keys/license-signing.pem', 'keys/license-public.pem', 'keys/auth-signing.pem',
  'keys/auth-public.pem', 'keys/wrapping-key',
] as const;

interface BackupMetadata {
  format: 1;
  recordedAt: string;
  scope: 'standalone-postgres-local-keys';
  secrets: { path: string; sha256: string; data: string }[];
}
function sha256(data: Buffer): string { return createHash('sha256').update(data).digest('hex'); }

export async function readBackupPassphrase(path: string): Promise<Buffer> {
  const info = await lstat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 4096) {
    throw new Error('Backup passphrase must be a private regular file (mode 0600)');
  }
  const text = (await readFile(path, 'utf8')).trim();
  if (text.length < 32 || !/^[\x21-\x7e]+$/.test(text)) throw new Error('Use at least 32 printable non-space characters for the backup passphrase');
  return Buffer.from(text);
}

async function deriveKey(passphrase: Buffer, salt: Buffer): Promise<Buffer> {
  return new Promise((resolveKey, reject) => scrypt(passphrase, salt, 32,
    { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
    (error, key) => error ? reject(error) : resolveKey(key)));
}

async function snapshotSecrets(directory: string): Promise<BackupMetadata['secrets']> {
  const result: BackupMetadata['secrets'] = [];
  for (const path of SECRET_PATHS) {
    const info = await lstat(join(directory, path));
    if (!info.isFile() || info.size < 1 || info.size > 64 * 1024) throw new Error(`Invalid secret file: ${path}`);
    const bytes = await readFile(join(directory, path));
    result.push({ path, sha256: sha256(bytes), data: bytes.toString('base64') });
    bytes.fill(0);
  }
  return result;
}

/** Streams the dump directly through authenticated encryption. Never publishes an incomplete archive. */
export async function createStandaloneArchive(
  destination: string, secretDirectory: string, passphrase: Buffer, dump: AsyncIterable<Buffer>,
): Promise<{ recordedAt: string; backupBytes: number; backupSha256: string }> {
  const metadata: BackupMetadata = { format: 1, recordedAt: new Date().toISOString(),
    scope: 'standalone-postgres-local-keys', secrets: await snapshotSecrets(secretDirectory) };
  const json = Buffer.from(JSON.stringify(metadata));
  const length = Buffer.alloc(4); length.writeUInt32BE(json.length);
  const salt = randomBytes(16), iv = randomBytes(12);
  const header = Buffer.concat([MAGIC, salt, iv]);
  const key = await deriveKey(passphrase, salt);
  const output = resolve(destination);
  const temporary = join(dirname(output), `.drm-backup-${randomBytes(16).toString('hex')}.partial`);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(header);
    await writeFile(temporary, header, { flag: 'wx', mode: 0o600 });
    let dumpBytes = 0;
    async function* plaintext(): AsyncGenerator<Buffer> {
      yield length; yield json;
      for await (const chunk of dump) {
        dumpBytes += chunk.length;
        if (dumpBytes > MAX_ARCHIVE - MAX_METADATA) throw new Error('Backup exceeds the 1 TiB supported limit');
        yield chunk;
      }
      if (dumpBytes < 5) throw new Error('Database dump is empty');
    }
    await pipeline(Readable.from(plaintext()), cipher, createWriteStream(temporary, { flags: 'a', mode: 0o600 }));
    const current = await snapshotSecrets(secretDirectory);
    if (JSON.stringify(current) !== JSON.stringify(metadata.secrets)) throw new Error('Secrets changed during backup; retry after key maintenance');
    await appendFile(temporary, cipher.getAuthTag());
    const handle = await open(temporary, 'r+');
    try { await handle.sync(); } finally { await handle.close(); }
    // Hard-link publication is atomic and refuses to replace an existing backup.
    await link(temporary, output);
    const directoryHandle = await open(dirname(output), 'r');
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(output)) hash.update(chunk);
    return { recordedAt: metadata.recordedAt, backupBytes: (await lstat(output)).size, backupSha256: hash.digest('hex') };
  } finally {
    key.fill(0); json.fill(0);
    await rm(temporary, { force: true });
  }
}

function validateMetadata(value: unknown): BackupMetadata {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid backup metadata');
  const data = value as BackupMetadata;
  if (Object.keys(data).sort().join(',') !== 'format,recordedAt,scope,secrets' || data.format !== 1 ||
      typeof data.recordedAt !== 'string' || !Number.isFinite(Date.parse(data.recordedAt)) ||
      data.scope !== 'standalone-postgres-local-keys' || !Array.isArray(data.secrets) || data.secrets.length !== SECRET_PATHS.length) {
    throw new Error('Unsupported backup metadata');
  }
  const paths = new Set<string>();
  for (const entry of data.secrets) {
    if (!entry || typeof entry !== 'object' || Object.keys(entry).sort().join(',') !== 'data,path,sha256' ||
        !SECRET_PATHS.includes(entry.path as typeof SECRET_PATHS[number]) || paths.has(entry.path) ||
        typeof entry.data !== 'string' || entry.data.length > 90_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(entry.data) ||
        typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error('Invalid backup secret');
    const bytes = Buffer.from(entry.data, 'base64');
    if (bytes.length < 1 || bytes.length > 64 * 1024 || bytes.toString('base64') !== entry.data || sha256(bytes) !== entry.sha256) {
      throw new Error('Backup secret checksum mismatch');
    }
    bytes.fill(0); paths.add(entry.path);
  }
  return data;
}

/** Authenticity is checked in a private temporary file before any recovered files are exposed. */
export async function extractStandaloneArchive(
  archive: string, destination: string, passphrase: Buffer,
): Promise<{ recordedAt: string; dumpBytes: number; recoveredSecrets: number }> {
  const info = await lstat(archive);
  if (!info.isFile() || info.size < HEADER_BYTES + 16 + 9 || info.size > MAX_ARCHIVE) throw new Error('Invalid backup file size or type');
  const input = await open(archive, 'r');
  const header = Buffer.alloc(HEADER_BYTES), tag = Buffer.alloc(16);
  try {
    await input.read(header, 0, header.length, 0);
    await input.read(tag, 0, tag.length, info.size - 16);
  } finally { await input.close(); }
  if (!header.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Unsupported backup format');
  const key = await deriveKey(passphrase, header.subarray(MAGIC.length, MAGIC.length + 16));
  const staging = await mkdtemp(join(tmpdir(), 'drm-recovery-'));
  const plaintext = join(staging, 'authenticated.dump');
  const output = resolve(destination);
  let created = false;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(MAGIC.length + 16));
    decipher.setAAD(header); decipher.setAuthTag(tag);
    await pipeline(createReadStream(archive, { start: HEADER_BYTES, end: info.size - 17 }), decipher,
      createWriteStream(plaintext, { flags: 'wx', mode: 0o600 }));
    const handle = await open(plaintext, 'r');
    let metadata: BackupMetadata;
    let offset: number;
    try {
      const length = Buffer.alloc(4);
      if ((await handle.read(length, 0, 4, 0)).bytesRead !== 4) throw new Error('Truncated backup metadata');
      const bytes = length.readUInt32BE();
      if (bytes < 1 || bytes > MAX_METADATA) throw new Error('Backup metadata is too large');
      const json = Buffer.alloc(bytes);
      if ((await handle.read(json, 0, bytes, 4)).bytesRead !== bytes) throw new Error('Truncated backup metadata');
      metadata = validateMetadata(JSON.parse(json.toString()));
      json.fill(0); offset = 4 + bytes;
      const signature = Buffer.alloc(5);
      if ((await handle.read(signature, 0, 5, offset)).bytesRead !== 5 || signature.toString() !== 'PGDMP') {
        throw new Error('Backup does not contain a PostgreSQL custom-format dump');
      }
    } finally { await handle.close(); }
    await mkdir(output, { mode: 0o700 }); created = true;
    await mkdir(join(output, 'database'), { mode: 0o700 });
    await mkdir(join(output, 'keys'), { mode: 0o700 });
    for (const entry of metadata.secrets) {
      const bytes = Buffer.from(entry.data, 'base64');
      try { await writeFile(join(output, entry.path), bytes, { flag: 'wx', mode: 0o600 }); }
      finally { bytes.fill(0); }
    }
    await pipeline(createReadStream(plaintext, { start: offset }),
      createWriteStream(join(output, 'database.dump'), { flags: 'wx', mode: 0o600 }));
    const report = { recordedAt: metadata.recordedAt, dumpBytes: (await lstat(join(output, 'database.dump'))).size,
      recoveredSecrets: metadata.secrets.length };
    await writeFile(join(output, 'recovery.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return report;
  } catch (error) {
    if (created) await rm(output, { recursive: true, force: true });
    throw error;
  } finally {
    key.fill(0);
    await rm(staging, { recursive: true, force: true });
  }
}
