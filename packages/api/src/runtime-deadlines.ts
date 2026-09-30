import type { Pool } from 'pg';

export async function endPoolWithin(pool: Pool, milliseconds = 15_000): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      pool.end(),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Database shutdown timed out')), milliseconds); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function armHardStop(milliseconds = 25_000): void {
  const timer = setTimeout(() => {
    process.stderr.write(JSON.stringify({ event: 'runtime.hard_stop' }) + '\n');
    process.exit(1);
  }, milliseconds);
  timer.unref();
}
