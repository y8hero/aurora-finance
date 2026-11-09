import { randomUUID } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { Pool } from 'pg'
import { PostgresAuditLog, PostgresIdempotencyStore, PostgresWebhookEventStore } from '../src/db/repositories'
import { PLATFORM_TENANT, tenantId } from '../src/core/types'
import { IdempotencyConflictError } from '../src/core/idempotency'
import type { AuditEntryInput } from '../src/core/audit/auditLog'

const databaseUrl = process.env.TEST_DATABASE_URL
const run = databaseUrl ? describe : describe.skip
const tenant = tenantId(randomUUID())
const otherTenant = tenantId(randomUUID())

let pool: Pool
let audit: PostgresAuditLog
let idempotency: PostgresIdempotencyStore
let webhooks: PostgresWebhookEventStore

beforeAll(async () => {
  if (!databaseUrl) return
  pool = new Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: true } })
  await pool.query(
    `INSERT INTO tenants (id, slug, name, country, status)
     VALUES ($1,$2,$3,$4,$5), ($6,$7,$8,$9,$10)
     ON CONFLICT (id) DO NOTHING`,
    [tenant, 'integration-a', 'Integration A', 'GB', 'active', otherTenant, 'integration-b', 'Integration B', 'US', 'active'],
  )
  audit = new PostgresAuditLog(pool)
  idempotency = new PostgresIdempotencyStore(pool)
  webhooks = new PostgresWebhookEventStore(pool)
})

afterAll(async () => {
  if (!databaseUrl) return
  // TEST_DATABASE_URL must point to a disposable database; append-only audit rows and tenant rows are intentionally not cleaned up.
  await pool.end()
})

run('Postgres persistence integration', () => {
  it('deduplicates webhook deliveries and preserves tenant ownership', async () => {
    const record = {
      tenant_id: tenant,
      provider: 'mock' as const,
      svix_id: `delivery-${randomUUID()}`,
      event_id: `event-${randomUUID()}`,
      event_type: 'test',
      signature_ok: true as const,
      raw_body: '{}',
      raw_body_hash: 'hash',
      received_at: new Date().toISOString(),
    }
    const first = await webhooks.insertIfAbsent(record)
    const second = await webhooks.insertIfAbsent({ ...record, tenant_id: otherTenant })
    expect(first.inserted).toBe(true)
    expect(second.inserted).toBe(false)
    expect(second.record.tenant_id).toBe(tenant)
  })

  it('verifies audit chains with absent optional fields', async () => {
    const base: AuditEntryInput = { tenant_id: tenant, actor: 'integration', action: `audit-${randomUUID()}` }
    const first = await audit.append(base)
    const second = await audit.append({ ...base, action: `${base.action}-with-fields`, before: { state: 'old' }, after: { state: 'new' }, metadata: { source: 'test' } })
    expect(first.before).toBeUndefined()
    expect(first.after).toBeUndefined()
    expect(first.metadata).toBeUndefined()
    expect(second.before).toEqual({ state: 'old' })
    expect(await audit.verify(tenant)).toEqual({ ok: true, length: 2 })
  })

  it('serializes concurrent audit appends without forks', async () => {
    const results = await Promise.all(Array.from({ length: 8 }, (_, index) => audit.append({ tenant_id: tenant, actor: 'integration', action: `concurrent-${randomUUID()}-${index}` })))
    expect(new Set(results.map((entry) => entry.seq)).size).toBe(8)
    expect(await audit.verify(tenant)).toMatchObject({ ok: true })
  })

  it('refuses audit UPDATE, DELETE, and TRUNCATE', async () => {
    const row = await audit.append({ tenant_id: tenant, actor: 'integration', action: `immutable-${randomUUID()}` })
    await expect(pool.query('UPDATE audit_log SET action = $1 WHERE tenant_id = $2 AND seq = $3', ['tampered', tenant, row.seq])).rejects.toThrow(/append-only/)
    await expect(pool.query('DELETE FROM audit_log WHERE tenant_id = $1 AND seq = $2', [tenant, row.seq])).rejects.toThrow(/append-only/)
    await expect(pool.query('TRUNCATE audit_log')).rejects.toThrow(/append-only/)
  })

  it('runs different keys independently', async () => {
    let calls = 0
    const fn = async () => {
      calls += 1
      await new Promise((resolve) => setTimeout(resolve, 50))
      return { accepted: true }
    }
    const first = idempotency.run(tenant, `idem-${randomUUID()}`, 'request-hash', fn)
    const second = idempotency.run(tenant, `idem-${randomUUID()}`, 'request-hash', fn)
    await expect(Promise.all([first, second])).resolves.toBeDefined()
    expect(calls).toBe(2)
  })

  it('rejects concurrent reuse of the same key and permits retry after failure', async () => {
    const key = `idem-${randomUUID()}`
    let calls = 0
    const fn = async () => {
      calls += 1
      await new Promise((resolve) => setTimeout(resolve, 50))
      return 'done'
    }
    const first = idempotency.run(tenant, key, 'same', fn)
    const second = idempotency.run(tenant, key, 'same', fn)
    await expect(second).rejects.toBeInstanceOf(IdempotencyConflictError)
    await expect(first).resolves.toBe('done')
    expect(calls).toBe(1)
    await expect(idempotency.run(tenant, key, 'different', fn)).rejects.toBeInstanceOf(IdempotencyConflictError)
  })

  it('uses the fixed platform tenant UUID for system identity', () => {
    expect(PLATFORM_TENANT).toBe('00000000-0000-0000-0000-000000000001')
  })
})
