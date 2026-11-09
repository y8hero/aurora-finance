import { describe, expect, it, vi } from 'vitest'
import {
  failureOutput,
  formatDbCheckError,
  printDbCheckOutput,
  successOutput,
} from '../scripts/db-check'

describe('database check error formatting', () => {
  it('never includes a connection string or credentials', () => {
    const connectionString =
      'postgresql://db_user:super-secret@example.supabase.co:5432/postgres?sslmode=require'

    const formatted = formatDbCheckError(
      Object.assign(
        new Error(
          `connect failed for ${connectionString}; password=super-secret`,
        ),
        { code: 'ECONNREFUSED' },
      ),
      connectionString,
    )

    expect(formatted.code).toBe('ECONNREFUSED')
    expect(formatted.message).not.toContain(connectionString)
    expect(formatted.message).not.toContain('super-secret')
    expect(formatted.message).not.toContain('example.supabase.co')
    expect(formatted.message).not.toContain('db_user')
  })

  it('produces output for both success and failure', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined)

    printDbCheckOutput(
      successOutput(
        true,
        new Map([
          ['tenants', '1'],
          ['provider_customers', '2'],
          ['webhook_events', '3'],
          ['audit_log', '4'],
          ['idempotency_keys', '5'],
        ]),
        true,
        '2',
      ),
    )

    printDbCheckOutput(
      failureOutput(
        Object.assign(new Error('connection refused'), {
          code: 'ECONNREFUSED',
        }),
      ),
    )

    expect(log).toHaveBeenCalledWith('connected: yes')
    expect(log).toHaveBeenCalledWith('connected: no')
    expect(log).toHaveBeenCalledWith('error code: ECONNREFUSED')

    log.mockRestore()
  })
})
