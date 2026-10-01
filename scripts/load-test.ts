import { writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';

function integer(value: string | undefined, name: string, min: number, max: number): number {
  const number = Number(value);
  if (!value || !Number.isSafeInteger(number) || number < min || number > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return number;
}

function threshold(value: string | undefined, name: string, fallback: number): number {
  const number = value === undefined ? fallback : Number(value);
  if (!Number.isFinite(number) || number < 0) throw new Error(`${name} must be nonnegative`);
  return number;
}

function percentile(sorted: number[], fraction: number): number | null {
  if (!sorted.length) return null;
  return Math.round(sorted[Math.ceil(sorted.length * fraction) - 1]! * 100) / 100;
}

async function main(): Promise<void> {
  const target = new URL(process.argv[2] ?? '');
  const local = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(target.hostname);
  if ((!local && (target.protocol !== 'https:' || process.env.LOAD_ALLOW_REMOTE !== '1')) ||
      (local && !['http:', 'https:'].includes(target.protocol)) ||
      target.username || target.password || target.hash ||
      !['/health/ready', '/v1/library', '/v1/creator/assets'].includes(target.pathname) ||
      (target.pathname === '/health/ready' && target.search)) {
    throw new Error('Use a supported health/catalog URL; remote HTTPS requires LOAD_ALLOW_REMOTE=1');
  }
  const durationSeconds = integer(process.argv[3], 'durationSeconds', 1, 600);
  const concurrency = integer(process.argv[4], 'concurrency', 1, 64);
  const rps = integer(process.env.LOAD_RPS ?? '10', 'LOAD_RPS', 1, 500);
  const maxP95Ms = threshold(process.env.LOAD_MAX_P95_MS, 'LOAD_MAX_P95_MS', 500);
  const maxErrorRate = threshold(process.env.LOAD_MAX_ERROR_RATE, 'LOAD_MAX_ERROR_RATE', 0.01);
  if (maxErrorRate > 1) throw new Error('LOAD_MAX_ERROR_RATE must be at most 1');
  const token = process.env.LOAD_BEARER_TOKEN;
  if (target.pathname !== '/health/ready' && !token) throw new Error('LOAD_BEARER_TOKEN is required for catalog routes');
  const start = performance.now();
  const deadline = start + durationSeconds * 1000;
  let sequence = 0;
  let completed = 0;
  let failures = 0;
  const latencies: number[] = [];
  const statuses: Record<string, number> = {};
  const worker = async () => {
    while (true) {
      const scheduled = start + sequence++ * 1000 / rps;
      if (scheduled >= deadline) return;
      const delay = scheduled - performance.now();
      if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
      const began = performance.now();
      try {
        const response = await fetch(target, {
          redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(10_000),
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        statuses[String(response.status)] = (statuses[String(response.status)] ?? 0) + 1;
        if (response.status !== 200) failures++;
        await response.body?.cancel();
      } catch {
        statuses.network = (statuses.network ?? 0) + 1;
        failures++;
      }
      latencies.push(performance.now() - began);
      completed++;
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  latencies.sort((a, b) => a - b);
  const elapsedSeconds = (performance.now() - start) / 1000;
  const report = {
    recordedAt: new Date().toISOString(), target: `${target.origin}${target.pathname}`,
    durationSeconds, concurrency, requestedRps: rps,
    completed, failures, statusCounts: statuses,
    observedRps: Math.round(completed / elapsedSeconds * 100) / 100,
    p50Ms: percentile(latencies, 0.5), p95Ms: percentile(latencies, 0.95),
    p99Ms: percentile(latencies, 0.99), maxP95Ms, maxErrorRate,
    passed: completed > 0 && failures / completed <= maxErrorRate && (percentile(latencies, 0.95) ?? Infinity) <= maxP95Ms,
  };
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (process.env.LOAD_REPORT_FILE) {
    await writeFile(process.env.LOAD_REPORT_FILE, output, { flag: 'wx', mode: 0o600 });
  }
  process.stdout.write(output);
  if (!report.passed) process.exitCode = 1;
}

void main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Load test failed'}\n`);
  process.exitCode = 2;
});
