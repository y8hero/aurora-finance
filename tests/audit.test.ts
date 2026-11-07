import { describe, expect, it } from 'vitest'
import { InMemoryAuditLog } from '../src/core/audit/auditLog'
import { tenantId } from '../src/core/types'

const tbc = tenantId('tbc')
const other = tenantId('other-tenant')

describe('append-only audit log', () => {
  it('exposes no update or delete API', () => {
    const log = new InMemoryAuditLog()
    const proto = Object.getPrototypeOf(log) as object
    const methods = Object.getOwnPropertyNames(proto).filter((m) => !m.startsWith('_'))
    expect(methods.sort()).toEqual(['append', 'constructor', 'list', 'verify'])
  })

  it('chains entries per tenant and verifies', async () => {
    const log = new InMemoryAuditLog()
    const a = await log.append({ tenant_id: tbc, actor: 'system', action: 'tenant.created', after: { name: 'TBC' } })
    const b = await log.append({ tenant_id: tbc, actor: 'walter', action: 'config.changed', before: { x: 1 }, after: { x: 2 } })
    expect(a.seq).toBe(1)
    expect(b.seq).toBe(2)
    expect(a.prev_hash).toBe('GENESIS')
    expect(b.prev_hash).toBe(a.hash)
    expect(await log.verify(tbc)).toEqual({ ok: true, length: 2 })
  })

  it('detects tampering', async () => {
    const log = new InMemoryAuditLog()
    await log.append({ tenant_id: tbc, actor: 'system', action: 'a' })
    await log.append({ tenant_id: tbc, actor: 'system', action: 'b' })
    await log.append({ tenant_id: tbc, actor: 'system', action: 'c' })
    log._unsafeTamperForTests(tbc, 2, (e) => ({ ...e, action: 'b-modified' }))
    const v = await log.verify(tbc)
    expect(v.ok).toBe(false)
    expect(v.brokenAtSeq).toBe(2)
  })

  it('returns frozen entries', async () => {
    const log = new InMemoryAuditLog()
    const e = await log.append({ tenant_id: tbc, actor: 'system', action: 'a' })
    expect(Object.isFrozen(e)).toBe(true)
    expect(Object.isFrozen(await log.list(tbc))).toBe(true)
  })

  it('isolates tenants', async () => {
    const log = new InMemoryAuditLog()
    await log.append({ tenant_id: tbc, actor: 'system', action: 'a' })
    await log.append({ tenant_id: other, actor: 'system', action: 'z' })
    const tbcEntries = await log.list(tbc)
    const otherEntries = await log.list(other)
    expect(tbcEntries).toHaveLength(1)
    expect(otherEntries).toHaveLength(1)
    expect(tbcEntries[0]?.action).toBe('a')
    expect(otherEntries[0]?.seq).toBe(1)
  })
})
