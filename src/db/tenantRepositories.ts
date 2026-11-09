import { randomUUID } from 'node:crypto'
import type { Pool } from 'pg'
import type { TenantId } from '../core/types'
import { PLATFORM_TENANT } from '../core/types'
import type { ApiKeyRecord, ApiKeyRepository, ApiKeyScope, ApiKeyStatus } from '../core/apiKeys'
import type { CustomerCreateInput, CustomerRecord, CustomerRepository } from '../core/customers'

type Row = Record<string, unknown>

const platformTenant = (tenantId: TenantId): void => {
  if (tenantId === PLATFORM_TENANT) throw new Error('Platform tenant cannot own API keys or customers')
}

function asApiKey(row: Row): ApiKeyRecord {
  return {
    id: String(row.id),
    tenant_id: String(row.tenant_id) as TenantId,
    key_prefix: String(row.key_prefix),
    scopes: Object.freeze((row.scopes as string[]).map((scope) => scope as ApiKeyScope)),
    status: row.status as ApiKeyStatus,
    created_at: new Date(String(row.created_at)).toISOString(),
    ...(row.last_used_at != null ? { last_used_at: new Date(String(row.last_used_at)).toISOString() } : {}),
  }
}

function asCustomer(row: Row): CustomerRecord {
  return {
    id: String(row.id),
    tenant_id: String(row.tenant_id) as TenantId,
    ...(row.external_ref != null ? { external_ref: String(row.external_ref) } : {}),
    first_name: String(row.first_name),
    last_name: String(row.last_name),
    email: String(row.email),
    country: String(row.country),
    kyc_tier: Number(row.kyc_tier) as CustomerRecord['kyc_tier'],
    status: String(row.status),
    created_at: new Date(String(row.created_at)).toISOString(),
  }
}

export class InMemoryApiKeyRepository implements ApiKeyRepository {
  private readonly rows = new Map<string, { record: ApiKeyRecord; hash: string }>()

  async create(input: Parameters<ApiKeyRepository['create']>[0]): Promise<ApiKeyRecord> {
    platformTenant(input.tenant_id)
    const record: ApiKeyRecord = {
      id: input.id,
      tenant_id: input.tenant_id,
      key_prefix: input.key_prefix,
      scopes: Object.freeze([...input.scopes]),
      status: 'active',
      created_at: new Date().toISOString(),
    }
    this.rows.set(input.key_hash, { record, hash: input.key_hash })
    return record
  }

  async findActiveByKeyHash(keyHash: string): Promise<ApiKeyRecord | undefined> {
    const row = this.rows.get(keyHash)
    return row?.record.status === 'active' ? row.record : undefined
  }

  async listByTenant(tenantId: TenantId): Promise<readonly ApiKeyRecord[]> {
    platformTenant(tenantId)
    return Object.freeze([...this.rows.values()].filter((row) => row.record.tenant_id === tenantId).map((row) => row.record))
  }

  async revoke(tenantId: TenantId, id: string): Promise<void> {
    platformTenant(tenantId)
    const row = [...this.rows.values()].find((entry) => entry.record.id === id)
    if (!row || row.record.tenant_id !== tenantId) throw new Error('API key not found for tenant')
    row.record = Object.freeze({ ...row.record, status: 'revoked' })
  }

  async touchLastUsed(id: string): Promise<void> {
    const row = [...this.rows.values()].find((entry) => entry.record.id === id)
    if (!row) throw new Error('API key not found')
    row.record = Object.freeze({ ...row.record, last_used_at: new Date().toISOString() })
  }
}

export class InMemoryCustomerRepository implements CustomerRepository {
  private readonly rows = new Map<string, CustomerRecord>()

  async create(tenantId: TenantId, input: CustomerCreateInput): Promise<CustomerRecord> {
    platformTenant(tenantId)
    if (input.external_ref && [...this.rows.values()].some((row) => row.tenant_id === tenantId && row.external_ref === input.external_ref)) {
      throw new Error('customer external_ref already exists for tenant')
    }
    const record: CustomerRecord = {
      id: randomUUID(),
      tenant_id: tenantId,
      ...(input.external_ref !== undefined ? { external_ref: input.external_ref } : {}),
      first_name: input.first_name,
      last_name: input.last_name,
      email: input.email,
      country: input.country,
      kyc_tier: input.kyc_tier ?? 0,
      status: input.status ?? 'active',
      created_at: new Date().toISOString(),
    }
    this.rows.set(record.id, record)
    return record
  }

  async get(tenantId: TenantId, id: string): Promise<CustomerRecord | undefined> {
    platformTenant(tenantId)
    const row = this.rows.get(id)
    return row?.tenant_id === tenantId ? row : undefined
  }

  async getByExternalRef(tenantId: TenantId, ref: string): Promise<CustomerRecord | undefined> {
    platformTenant(tenantId)
    return [...this.rows.values()].find((row) => row.tenant_id === tenantId && row.external_ref === ref)
  }

  async list(tenantId: TenantId, limit: number, cursor?: string): Promise<readonly CustomerRecord[]> {
    platformTenant(tenantId)
    const rows = [...this.rows.values()].filter((row) => row.tenant_id === tenantId).sort((a, b) => a.id.localeCompare(b.id))
    const start = cursor ? Math.max(0, rows.findIndex((row) => row.id === cursor) + 1) : 0
    return Object.freeze(rows.slice(start, start + Math.min(Math.max(1, limit), 100)))
  }
}

export class PostgresApiKeyRepository implements ApiKeyRepository {
  constructor(private readonly pool: Pool) {}

  async create(input: Parameters<ApiKeyRepository['create']>[0]): Promise<ApiKeyRecord> {
    platformTenant(input.tenant_id)
    const result = await this.pool.query<Row>(
      `INSERT INTO api_keys (id, tenant_id, key_prefix, key_hash, scopes, status)
       VALUES ($1,$2,$3,$4,$5,'active')
       RETURNING id, tenant_id, key_prefix, scopes, status, created_at, last_used_at`,
      [input.id, input.tenant_id, input.key_prefix, input.key_hash, input.scopes],
    )
    return asApiKey(result.rows[0]!)
  }

  async findActiveByKeyHash(keyHash: string): Promise<ApiKeyRecord | undefined> {
    const result = await this.pool.query<Row>(
      `SELECT id, tenant_id, key_prefix, scopes, status, created_at, last_used_at
       FROM api_keys WHERE key_hash = $1 AND status = 'active'`,
      [keyHash],
    )
    return result.rows[0] ? asApiKey(result.rows[0]) : undefined
  }

  async listByTenant(tenantId: TenantId): Promise<readonly ApiKeyRecord[]> {
    platformTenant(tenantId)
    const result = await this.pool.query<Row>(
      `SELECT id, tenant_id, key_prefix, scopes, status, created_at, last_used_at
       FROM api_keys WHERE tenant_id = $1 ORDER BY created_at, id`,
      [tenantId],
    )
    return Object.freeze(result.rows.map(asApiKey))
  }

  async revoke(tenantId: TenantId, id: string): Promise<void> {
    platformTenant(tenantId)
    const result = await this.pool.query(
      `UPDATE api_keys SET status = 'revoked'
       WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    )
    if (result.rowCount !== 1) throw new Error('API key not found for tenant')
  }

  async touchLastUsed(id: string): Promise<void> {
    await this.pool.query(
      `UPDATE api_keys SET last_used_at = now()
       WHERE id = $1`,
      [id],
    )
  }
}

export class PostgresCustomerRepository implements CustomerRepository {
  constructor(private readonly pool: Pool) {}

  async create(tenantId: TenantId, input: CustomerCreateInput): Promise<CustomerRecord> {
    platformTenant(tenantId)
    const result = await this.pool.query<Row>(
      `INSERT INTO customers
       (tenant_id, external_ref, first_name, last_name, email, country, kyc_tier, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, tenant_id, external_ref, first_name, last_name, email, country, kyc_tier, status, created_at`,
      [tenantId, input.external_ref ?? null, input.first_name, input.last_name, input.email, input.country, input.kyc_tier ?? 0, input.status ?? 'active'],
    )
    return asCustomer(result.rows[0]!)
  }

  async get(tenantId: TenantId, id: string): Promise<CustomerRecord | undefined> {
    platformTenant(tenantId)
    const result = await this.pool.query<Row>(
      `SELECT id, tenant_id, external_ref, first_name, last_name, email, country, kyc_tier, status, created_at
       FROM customers WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    )
    return result.rows[0] ? asCustomer(result.rows[0]) : undefined
  }

  async getByExternalRef(tenantId: TenantId, ref: string): Promise<CustomerRecord | undefined> {
    platformTenant(tenantId)
    const result = await this.pool.query<Row>(
      `SELECT id, tenant_id, external_ref, first_name, last_name, email, country, kyc_tier, status, created_at
       FROM customers WHERE tenant_id = $1 AND external_ref = $2`,
      [tenantId, ref],
    )
    return result.rows[0] ? asCustomer(result.rows[0]) : undefined
  }

  async list(tenantId: TenantId, limit: number, cursor?: string): Promise<readonly CustomerRecord[]> {
    platformTenant(tenantId)
    const bounded = Math.min(Math.max(1, limit), 100)
    const result = cursor
      ? await this.pool.query<Row>(
          `SELECT id, tenant_id, external_ref, first_name, last_name, email, country, kyc_tier, status, created_at
           FROM customers WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`,
          [tenantId, cursor, bounded],
        )
      : await this.pool.query<Row>(
          `SELECT id, tenant_id, external_ref, first_name, last_name, email, country, kyc_tier, status, created_at
           FROM customers WHERE tenant_id = $1 ORDER BY id LIMIT $2`,
          [tenantId, bounded],
        )
    return Object.freeze(result.rows.map(asCustomer))
  }
}
