import type { TenantId, TenantRecord } from '../types'

export class TenantMismatchError extends Error {
  override name = 'TenantMismatchError'
}

/**
 * Generic tenant-scoped key/value store.
 *
 * Isolation rules:
 *  - There is no method that reads across tenants.
 *  - `put` refuses a record whose `tenant_id` does not match the scope it is written to.
 *  - All reads require a `tenant_id`.
 *
 * In-memory for Phase 1. Swap for a DB-backed implementation behind the same interface.
 */
export interface TenantScopedStore<T extends TenantRecord> {
  put(tenantId: TenantId, id: string, record: T): Promise<T>
  get(tenantId: TenantId, id: string): Promise<T | undefined>
  list(tenantId: TenantId): Promise<readonly T[]>
  count(tenantId: TenantId): Promise<number>
}

export class InMemoryTenantStore<T extends TenantRecord> implements TenantScopedStore<T> {
  private readonly byTenant = new Map<TenantId, Map<string, T>>()

  async put(tenantId: TenantId, id: string, record: T): Promise<T> {
    if (record.tenant_id !== tenantId) {
      throw new TenantMismatchError(
        `Refusing to write record with tenant_id=${record.tenant_id} into scope tenant_id=${tenantId}`,
      )
    }
    let bucket = this.byTenant.get(tenantId)
    if (!bucket) {
      bucket = new Map()
      this.byTenant.set(tenantId, bucket)
    }
    const frozen = Object.freeze({ ...record })
    bucket.set(id, frozen)
    return frozen
  }

  async get(tenantId: TenantId, id: string): Promise<T | undefined> {
    return this.byTenant.get(tenantId)?.get(id)
  }

  async list(tenantId: TenantId): Promise<readonly T[]> {
    return Object.freeze([...(this.byTenant.get(tenantId)?.values() ?? [])])
  }

  async count(tenantId: TenantId): Promise<number> {
    return this.byTenant.get(tenantId)?.size ?? 0
  }
}
