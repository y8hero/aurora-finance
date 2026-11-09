import { Pool, type PoolConfig } from 'pg'
import type { AppConfig } from '../config/env'

export function createDatabasePool(config: AppConfig): Pool | undefined {
  const databaseUrl = config.DATABASE_URL

  if (!databaseUrl) return undefined

  const poolConfig: PoolConfig = {
    connectionString: databaseUrl.reveal(),
    ssl: { rejectUnauthorized: true },
    max: 10,
    min: 0,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    statement_timeout: 15_000,
    query_timeout: 15_000,
    maxUses: 10_000,
  }

  return new Pool(poolConfig)
}

export async function closeDatabasePool(pool: Pool | undefined): Promise<void> {
  if (pool) await pool.end()
}
