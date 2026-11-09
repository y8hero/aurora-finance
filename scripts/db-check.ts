import { createDatabasePool, closeDatabasePool } from '../src/db/pool'
import { loadConfig } from '../src/config/env'

const TABLE_NAMES = [
  'tenants',
  'provider_customers',
  'webhook_events',
  'audit_log',
  'idempotency_keys',
] as const

export interface DbCheckErrorOutput {
  readonly code: string
  readonly message: string
}

export interface DbCheckOutput {
  readonly connected: boolean
  readonly lines: readonly string[]
}

function readErrorCode(error: unknown): string {
  if (
    error &&
    typeof error === 'object' &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    return error.code
  }

  return 'UNKNOWN'
}

function redactSensitiveConnectionParts(
  message: string,
  connectionString?: string,
): string {
  let result = message

  if (connectionString) {
    result = result.split(connectionString).join('[redacted-connection-string]')

    try {
      const parsed = new URL(connectionString)
      const sensitiveParts = [
        parsed.hostname,
        parsed.username,
        parsed.password,
        parsed.host,
      ]

      for (const part of sensitiveParts) {
        if (part.length > 0) {
          result = result.split(part).join('[redacted]')
        }
      }
    } catch {
      // The connection string was already replaced above.
    }
  }

  return result
    .replace(
      /((?:postgres(?:ql)?):\/\/)[^/\s]+(?=@|\/|$)/gi,
      '$1[redacted-credentials]',
    )
    .replace(
      /((?:password|pass|pwd)=)[^&\s]+/gi,
      '$1[redacted]',
    )
    .replace(/\s+/g, ' ')
    .trim()
}

export function formatDbCheckError(
  error: unknown,
  connectionString?: string,
): DbCheckErrorOutput {
  const message = error instanceof Error ? error.message : String(error)
  const redacted = redactSensitiveConnectionParts(message, connectionString)

  return {
    code: readErrorCode(error),
    message: redacted.slice(0, 240) || 'database check failed',
  }
}

export function successOutput(
  ssl: boolean,
  counts: ReadonlyMap<string, string>,
  platformTenantExists: boolean,
  auditTriggerCount: string,
): DbCheckOutput {
  return {
    connected: true,
    lines: [
      'connected: yes',
      `ssl: ${ssl ? 'true' : 'false'}`,
      ...TABLE_NAMES.map(
        (tableName) => `${tableName}: ${counts.get(tableName) ?? '0'}`,
      ),
      `platform tenant row: ${platformTenantExists ? 'yes' : 'no'}`,
      `audit_log triggers: ${auditTriggerCount}`,
    ],
  }
}

export function failureOutput(
  error: unknown,
  connectionString?: string,
): DbCheckOutput {
  const formatted = formatDbCheckError(error, connectionString)

  return {
    connected: false,
    lines: [
      'connected: no',
      `error code: ${formatted.code}`,
      `error message: ${formatted.message}`,
    ],
  }
}

export function printDbCheckOutput(output: DbCheckOutput): void {
  for (const line of output.lines) {
    console.log(line)
  }
}

function isPoolSslEnabled(pool: unknown): boolean {
  if (!pool || typeof pool !== 'object' || !('options' in pool)) {
    return false
  }

  const options = pool.options
  if (!options || typeof options !== 'object' || !('ssl' in options)) {
    return false
  }

  return Boolean(options.ssl)
}

async function main(): Promise<void> {
  let pool: ReturnType<typeof createDatabasePool> | undefined

  try {
    const config = loadConfig()

    if (!config.DATABASE_URL) {
      printDbCheckOutput({
        connected: false,
        lines: ['DATABASE_URL: not set'],
      })
      process.exitCode = 1
      return
    }

    pool = createDatabasePool(config)

    if (!pool) {
      printDbCheckOutput({
        connected: false,
        lines: [
          'connected: no',
          'error code: CONFIGURATION',
          'error message: database pool was not created',
        ],
      })
      process.exitCode = 1
      return
    }

    const result = await pool.query<{
      table_name: string
      row_count: string
    }>(`
      SELECT 'tenants' AS table_name, count(*)::text AS row_count FROM tenants
      UNION ALL
      SELECT 'provider_customers', count(*)::text FROM provider_customers
      UNION ALL
      SELECT 'webhook_events', count(*)::text FROM webhook_events
      UNION ALL
      SELECT 'audit_log', count(*)::text FROM audit_log
      UNION ALL
      SELECT 'idempotency_keys', count(*)::text FROM idempotency_keys
      ORDER BY table_name
    `)

    const platform = await pool.query<{ exists: boolean }>(
      `SELECT EXISTS (
         SELECT 1
         FROM tenants
         WHERE id = '00000000-0000-0000-0000-000000000001'::uuid
       ) AS exists`,
    )

    const triggers = await pool.query<{ trigger_count: string }>(
      `SELECT count(*)::text AS trigger_count
       FROM pg_trigger AS trigger_row
       JOIN pg_class AS table_row
         ON table_row.oid = trigger_row.tgrelid
       JOIN pg_namespace AS namespace_row
         ON namespace_row.oid = table_row.relnamespace
       WHERE namespace_row.nspname = current_schema()
         AND table_row.relname = 'audit_log'
         AND NOT trigger_row.tgisinternal`,
    )

    const counts = new Map(
      result.rows.map((row) => [row.table_name, row.row_count]),
    )

    printDbCheckOutput(
      successOutput(
        isPoolSslEnabled(pool),
        counts,
        platform.rows[0]?.exists === true,
        triggers.rows[0]?.trigger_count ?? '0',
      ),
    )
  } catch (error) {
    const connectionString = (() => {
      try {
        const config = loadConfig()
        return config.DATABASE_URL?.reveal()
      } catch {
        return undefined
      }
    })()

    printDbCheckOutput(failureOutput(error, connectionString))
    process.exitCode = 1
  } finally {
    await closeDatabasePool(pool)
  }
}

main()
  .catch((error: unknown) => {
    printDbCheckOutput(failureOutput(error))
    process.exitCode = 1
  })
  .finally(() => {
    // The main finally block owns pool cleanup. This keeps the top-level
    // promise chain from producing an unhandled rejection.
  })
