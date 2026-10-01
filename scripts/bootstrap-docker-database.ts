import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const directory = process.argv[2];
if (!directory) throw new Error('Usage: bootstrap-docker-database.ts <new-secret-directory>');
const target = resolve(directory);
mkdirSync(target, { mode: 0o700, recursive: false });
const write = (name: string, content: string) => writeFileSync(resolve(target, name), content, { mode: 0o600, flag: 'wx' });
for (const name of ['owner-password', 'api-password', 'worker-password']) write(name, `${randomBytes(32).toString('base64url')}\n`);
function openssl(...args: string[]): void {
  const run = spawnSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  if (run.status !== 0) throw new Error(`openssl failed: ${run.stderr.toString().trim()}`);
}
const caKey = resolve(target, 'ca.key');
const caCert = resolve(target, 'ca.crt');
const serverKey = resolve(target, 'server.key');
const serverCsr = resolve(target, 'server.csr');
const serverCert = resolve(target, 'server.crt');
const extensions = resolve(target, 'server.ext');
write('server.ext', 'subjectAltName=DNS:postgres\nextendedKeyUsage=serverAuth\n');
openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', caKey, '-out', caCert, '-subj', '/CN=DRM Local CA', '-days', '365');
openssl('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', serverKey, '-out', serverCsr, '-subj', '/CN=postgres');
openssl('x509', '-req', '-in', serverCsr, '-CA', caCert, '-CAkey', caKey, '-CAcreateserial', '-out', serverCert, '-days', '365', '-extfile', extensions);
chmodSync(caKey, 0o600);
chmodSync(serverKey, 0o600);
process.stdout.write(`Created Docker PostgreSQL credentials and TLS material in ${target}. Keep the CA key offline and renew the server certificate before expiry.\n`);
