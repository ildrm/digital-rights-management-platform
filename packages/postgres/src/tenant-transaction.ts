import type { Pool, PoolClient } from 'pg';
import { DomainError } from '@drm/core';

export async function withTenantTransaction<T>(pool: Pool, tenantId: string, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId)) {
    throw new DomainError('INVALID_TENANT', 'Tenant ID must be a UUID');
  }
  const client = await pool.connect();
  let released = false;
  try {
    await client.query('BEGIN');
    const role = await client.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
      'SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
    );
    if (role.rows[0]?.rolsuper || role.rows[0]?.rolbypassrls) {
      throw new DomainError('INSECURE_DATABASE_ROLE', 'Application connections must not bypass row security');
    }
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
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
  }
}
