import { spawnSync } from 'node:child_process';

export function operatorToken(tenantId: string, subject: string, scopes: string): string {
  const result = spawnSync('docker', ['compose', '-f', 'compose.standalone.yaml', '--progress=quiet',
    ...(process.env.COMPOSE_PROJECT_NAME ? ['-p', process.env.COMPOSE_PROJECT_NAME] : []),
    'run', '--rm', '--no-deps', 'operator', 'node', '--experimental-strip-types', 'scripts/issue-local-token.ts',
    '/run/secrets/auth-signing', 'drm-local', 'drm-api', tenantId, subject, scopes],
  { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000, maxBuffer: 1024 * 1024 });
  // Compose may emit build progress before the command's output. Never put captured token bytes in an exception.
  const tokens = result.stdout?.split(/\r?\n/).filter((line) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(line.trim())) ?? [];
  if (result.error || result.status !== 0 || tokens.length !== 1) throw new Error('Operator token issuance failed');
  return tokens[0]!.trim();
}
