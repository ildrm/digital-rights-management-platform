import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const directory = process.argv[2];
if (!directory) throw new Error('Usage: bootstrap-local-keys.ts <new-secret-directory>');
const target = resolve(directory);
mkdirSync(target, { mode: 0o700, recursive: false });
const write = (name: string, content: string) => writeFileSync(resolve(target, name), content, { mode: 0o600, flag: 'wx' });
const signing = generateKeyPairSync('ed25519');
const auth = generateKeyPairSync('ed25519');
write('license-signing.pem', signing.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
write('license-public.pem', signing.publicKey.export({ type: 'spki', format: 'pem' }).toString());
write('auth-signing.pem', auth.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
write('auth-public.pem', auth.publicKey.export({ type: 'spki', format: 'pem' }).toString());
write('wrapping-key', `${randomBytes(32).toString('base64url')}\n`);
process.stdout.write(`Created local key material in ${target}. Back up this directory securely; losing the wrapping key makes stored packages unreadable.\n`);
