import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SignJWT } from 'jose';

const [keyFile, issuer, audience, tenantId, subject, scopes] = process.argv.slice(2);
if (!keyFile || !issuer || !audience || !tenantId || !subject || !scopes ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId) ||
    subject.length > 256 || !/^(drm:license|drm:publish)( (drm:license|drm:publish))?$/.test(scopes)) {
  throw new Error('Usage: issue-local-token.ts <auth-signing.pem> <issuer> <audience> <tenant-uuid> <subject> <drm:license|drm:publish|both>');
}
const key = createPrivateKey(readFileSync(keyFile, 'utf8'));
if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 signing key required');
const token = await new SignJWT({ tenant_id: tenantId.toLowerCase(), scope: scopes })
  .setProtectedHeader({ alg: 'EdDSA' }).setIssuer(issuer).setAudience(audience)
  .setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(key);
process.stdout.write(`${token}\n`);
