import { randomUUID } from 'node:crypto'
import type { TenantId } from './types'
import { PLATFORM_TENANT } from './types'

export interface TenantRecord {
  readonly id: TenantId
  readonly slug: string
  readonly name: string
  readonly country: string
  readonly status: 'active' | 'suspended' | 'closed' | 'system'
  readonly created_at: string
}

export interface TenantCreateInput {
  readonly slug: string
  readonly name: string
  readonly country: string
}

export interface TenantRepository {
  create(input: TenantCreateInput): Promise<TenantRecord>
  list(): Promise<readonly TenantRecord[]>
  get(id: TenantId): Promise<TenantRecord | undefined>
}

export class InMemoryTenantRepository implements TenantRepository {
  private readonly rows = new Map<TenantId, TenantRecord>()

  constructor() {
    const platform: TenantRecord = {
      id: PLATFORM_TENANT,
      slug: 'platform',
      name: 'platform',
      country: 'ZZ',
      status: 'system',
      created_at: new Date().toISOString(),
    }
    this.rows.set(platform.id, platform)
  }

  async create(input: TenantCreateInput): Promise<TenantRecord> {
    const record: TenantRecord = {
      id: randomUUID() as TenantId,
      slug: input.slug,
      name: input.name,
      country: input.country,
      status: 'active',
      created_at: new Date().toISOString(),
    }
    if ([...this.rows.values()].some((row) => row.slug === input.slug)) {
      throw new Error('tenant slug already exists')
    }
    this.rows.set(record.id, record)
    return record
  }

  async list(): Promise<readonly TenantRecord[]> {
    return Object.freeze([...this.rows.values()])
  }

  async get(id: TenantId): Promise<TenantRecord | undefined> {
    return this.rows.get(id)
  }
}
