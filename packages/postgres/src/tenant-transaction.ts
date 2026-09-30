import type { Pool, PoolClient } from 'pg';
import { DomainError } from '@drm/core';

/** A failed COMMIT response cannot prove whether PostgreSQL committed the transaction. */
export class TransactionCommitUnknownError extends Error {
  constructor(cause: unknown) {
    super('PostgreSQL commit outcome is unknown', { cause });
    this.name = 'TransactionCommitUnknownError';
  }
}

export async function withTenantTransaction<T>(pool: Pool, tenantId: string, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId)) {
    throw new DomainError('INVALID_TENANT', 'Tenant ID must be a UUID');
  }
  let client: PoolClient;
  try { client = await pool.connect(); }
  catch { throw new DomainError('DATABASE_UNAVAILABLE', 'Database connection is unavailable'); }
  let connectionError: Error | undefined;
  const onConnectionError = (error: Error) => { connectionError = error; };
  client.on('error', onConnectionError);
  let released = false;
  let commitAttempted = false;
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout = '10000ms'");
    await client.query("SET LOCAL lock_timeout = '2000ms'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '25000ms'");
    const role = await client.query<{ rolsuper: boolean; rolbypassrls: boolean; owns_drm_table: boolean }>(
      `SELECT rolsuper, rolbypassrls, EXISTS (
         SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'drm' AND c.relkind IN ('r', 'p')
           AND pg_has_role(current_user, c.relowner, 'member')
       ) AS owns_drm_table
       FROM pg_roles WHERE rolname = current_user`,
    );
    if (role.rows[0]?.rolsuper || role.rows[0]?.rolbypassrls || role.rows[0]?.owns_drm_table) {
      throw new DomainError('INSECURE_DATABASE_ROLE', 'Application connections must not bypass row security');
    }
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await operation(client);
    if (connectionError) throw connectionError;
    commitAttempted = true;
    await client.query('COMMIT');
    return result;
  } catch (error) {
    if (commitAttempted) {
      client.release(true);
      released = true;
      throw new TransactionCommitUnknownError(error);
    }
    if (connectionError) {
      client.release(true);
      released = true;
      throw new DomainError('DATABASE_UNAVAILABLE', 'Database connection was lost');
    }
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      client.release(true);
      released = true;
      throw new AggregateError([error, rollbackError], 'Transaction and rollback both failed');
    }
    throw error;
  } finally {
    // A failed rollback has already destroyed the connection.
    if (!released) client.release();
    client.off('error', onConnectionError);
  }
}
