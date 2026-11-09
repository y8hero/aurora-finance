import { readFileSync } from 'node:fs'
import { Pool, type PoolConfig } from 'pg'
import type { AppConfig } from '../config/env'

export function createDatabasePool(config: AppConfig): Pool | undefined {
  if (!config.DATABASE_URL) return undefined

  const ssl: PoolConfig['ssl'] = config.DATABASE_CA_CERT_PATH
    ? {
        ca: readFileSync(config.DATABASE_CA_CERT_PATH, 'utf8'),
        rejectUnauthorized: true,
      }
    : { rejectUnauthorized: true }

  return new Pool({
    connectionString: config.DATABASE_URL.reveal(),
    ssl,
    max: 10,
    min: 0,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    statement_timeout: 15_000,
    query_timeout: 15_000,
    maxUses: 10_000,
  })
}

export async function closeDatabasePool(pool: Pool | undefined): Promise<void> {
  if (pool) await pool.end()
}
