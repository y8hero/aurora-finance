import { describe, expect, it } from 'vitest'
import { InMemoryTenantStore, TenantMismatchError } from '../src/core/store/tenantStore'
import { tenantId, type TenantRecord } from '../src/core/types'

interface Thing extends TenantRecord {
  readonly value: string
}

const tbc = tenantId('tbc')
const other = tenantId('other')

describe('tenant-scoped store', () => {
  it('refuses records written under the wrong tenant scope', async () => {
    const store = new InMemoryTenantStore<Thing>()
    await expect(store.put(tbc, 'x', { tenant_id: other, value: 'leak' })).rejects.toBeInstanceOf(TenantMismatchError)
  })

  it('never returns another tenant\'s records', async () => {
    const store = new InMemoryTenantStore<Thing>()
    await store.put(tbc, 'x', { tenant_id: tbc, value: 'secret' })
    expect(await store.get(other, 'x')).toBeUndefined()
    expect(await store.list(other)).toHaveLength(0)
    expect(await store.count(tbc)).toBe(1)
  })

  it('validates tenant ids', () => {
    expect(() => tenantId('')).toThrow()
    expect(() => tenantId('bad id with spaces')).toThrow()
    expect(() => tenantId('../etc')).toThrow()
    expect(tenantId('tbc_01')).toBe('tbc_01')
  })
})
