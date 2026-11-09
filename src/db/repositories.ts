import type { Pool, PoolClient } from 'pg'
import type { TenantId, ProviderName } from '../core/types'
import type { TenantScopedStore } from '../core/store/tenantStore'
import type { AuditEntry, AuditEntryInput, AuditLog, ChainVerification } from '../core/audit/auditLog'
import type { WebhookEventRecord, WebhookEventStore, InsertResult } from '../webhooks/eventStore'
import type { WebhookTenantResolver } from '../webhooks/receiver'
import { hashEntry, GENESIS_HASH } from '../core/audit/auditLog'
import { IdempotencyConflictError, type IdempotencyStore } from '../core/idempotency'

type Row = Record<string, unknown>

function asTenantId(value: unknown): TenantId {
  return String(value) as TenantId
}

function asWebhook(row: Row): WebhookEventRecord {
  return {
    tenant_id: asTenantId(row.tenant_id),
    provider: row.provider as ProviderName,
    svix_id: String(row.delivery_id),
    event_id: String(row.event_id),
    event_type: String(row.event_type),
    signature_ok: true,
    raw_body: String(row.raw_body),
    raw_body_hash: String(row.raw_body_hash),
    received_at: new Date(String(row.received_at)).toISOString(),
    ...(row.processed_at
      ? { processed_at: new Date(String(row.processed_at)).toISOString() }
      : {}),
  }
}

export class PostgresWebhookEventStore implements WebhookEventStore {
  constructor(private readonly pool: Pool) {}

  async insertIfAbsent(record: WebhookEventRecord): Promise<InsertResult> {
    const inserted = await this.pool.query<Row>(
      `INSERT INTO webhook_events
       (provider, delivery_id, tenant_id, event_id, event_type, raw_body, raw_body_hash, received_at, processed_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (provider, delivery_id) DO NOTHING
       RETURNING provider, delivery_id, tenant_id, event_id, event_type, raw_body, raw_body_hash, received_at, processed_at`,
      [
        record.provider,
        record.svix_id,
        record.tenant_id,
        record.event_id,
        record.event_type,
        record.raw_body,
        record.raw_body_hash,
        record.received_at,
        record.processed_at ?? null,
      ],
    )

    if (inserted.rows[0]) {
      return { inserted: true, record: asWebhook(inserted.rows[0]) }
    }

    const existing = await this.pool.query<Row>(
      `SELECT provider, delivery_id, tenant_id, event_id, event_type, raw_body, raw_body_hash, received_at, processed_at
       FROM webhook_events WHERE provider = $1 AND delivery_id = $2`,
      [record.provider, record.svix_id],
    )

    const row = existing.rows[0]
    if (!row) throw new Error('Webhook insert conflict but existing row was not found')
    return { inserted: false, record: asWebhook(row) }
  }

  async findByDelivery(provider: ProviderName, deliveryId: string): Promise<WebhookEventRecord | undefined> {
    const result = await this.pool.query<Row>(
      `SELECT provider, delivery_id, tenant_id, event_id, event_type, raw_body, raw_body_hash, received_at, processed_at
       FROM webhook_events WHERE provider = $1 AND delivery_id = $2`,
      [provider, deliveryId],
    )
    return result.rows[0] ? asWebhook(result.rows[0]) : undefined
  }

  async markProcessed(tenantId: TenantId, provider: ProviderName, deliveryId: string, at: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE webhook_events SET processed_at = $1
       WHERE tenant_id = $2 AND provider = $3 AND delivery_id = $4`,
      [at, tenantId, provider, deliveryId],
    )
    if (result.rowCount !== 1) throw new Error('Webhook event not found for tenant')
  }

  async list(tenantId: TenantId): Promise<readonly WebhookEventRecord[]> {
    const result = await this.pool.query<Row>(
      `SELECT provider, delivery_id, tenant_id, event_id, event_type, raw_body, raw_body_hash, received_at, processed_at
       FROM webhook_events WHERE tenant_id = $1 ORDER BY received_at`,
      [tenantId],
    )
    return Object.freeze(result.rows.map(asWebhook))
  }
}

function asAudit(row: Row): AuditEntry {
  return {
    tenant_id: asTenantId(row.tenant_id),
    id: String(row.id),
    seq: Number(row.seq),
    timestamp: new Date(String(row.created_at)).toISOString(),
    actor: String(row.actor),
    action: String(row.action),
    prev_hash: String(row.prev_hash),
    hash: String(row.hash),
    ...(row.metadata ? { metadata: row.metadata as Record<string, unknown> } : {}),
  }
}

export class PostgresAuditLog implements AuditLog {
  constructor(private readonly pool: Pool) {}

  async append(input: AuditEntryInput): Promise<AuditEntry> {
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.tenant_id])

      const previous = await client.query<Row>(
        `SELECT seq, hash FROM audit_log
         WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
        [input.tenant_id],
      )
      const prev = previous.rows[0]
      const seq = prev ? Number(prev.seq) + 1 : 1
      const prevHash = prev ? String(prev.hash) : GENESIS_HASH
      const createdAt = new Date().toISOString()
      const unhashed = {
        ...input,
        id: crypto.randomUUID(),
        seq,
        timestamp: createdAt,
        prev_hash: prevHash,
      }
      const hash = hashEntry(unhashed)

      const inserted = await client.query<Row>(
        `INSERT INTO audit_log
         (tenant_id, seq, prev_hash, hash, actor, action, metadata, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         RETURNING id, tenant_id, seq, prev_hash, hash, actor, action, metadata, created_at`,
        [
          input.tenant_id,
          seq,
          prevHash,
          hash,
          input.actor,
          input.action,
          JSON.stringify(input.metadata ?? {}),
          createdAt,
        ],
      )

      await client.query('COMMIT')
      return asAudit(inserted.rows[0]!)
    } catch (error) {
      await client.query('ROLLBACK')
      throw error
    } finally {
      client.release()
    }
  }

  async list(tenantId: TenantId): Promise<readonly AuditEntry[]> {
    const result = await this.pool.query<Row>(
      `SELECT id, tenant_id, seq, prev_hash, hash, actor, action, metadata, created_at
       FROM audit_log WHERE tenant_id = $1 ORDER BY seq`,
      [tenantId],
    )
    return Object.freeze(result.rows.map(asAudit))
  }

  async verify(tenantId: TenantId): Promise<ChainVerification> {
    const entries = await this.list(tenantId)
    let previous = GENESIS_HASH

    for (const entry of entries) {
      const { hash, ...rest } = entry
      if (entry.prev_hash !== previous || hashEntry(rest) !== hash) {
        return { ok: false, length: entries.length, brokenAtSeq: entry.seq }
      }
      previous = hash
    }

    return { ok: true, length: entries.length }
  }
}

export class PostgresProviderCustomerResolver implements WebhookTenantResolver {
  constructor(private readonly pool: Pool) {}

  async resolve(provider: ProviderName, providerCustomerId: string): Promise<TenantId | undefined> {
    const result = await this.pool.query<{ tenant_id: string }>(
      `SELECT tenant_id FROM provider_customers
       WHERE provider = $1 AND provider_customer_id = $2`,
      [provider, providerCustomerId],
    )
    return result.rows[0] ? asTenantId(result.rows[0].tenant_id) : undefined
  }
}

export interface PostgresIdempotencyRecord {
  readonly tenant_id: TenantId
  readonly key: string
  readonly request_hash: string
  readonly response: unknown
  readonly created_at: string
}

export class PostgresIdempotencyStore {
  constructor(private readonly pool: Pool) {}

  async get(tenantId: TenantId, key: string): Promise<PostgresIdempotencyRecord | undefined> {
    const result = await this.pool.query<Row>(
      `SELECT tenant_id, key, request_hash, response, created_at
       FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
      [tenantId, key],
    )
    const row = result.rows[0]
    return row
      ? {
          tenant_id: asTenantId(row.tenant_id),
          key: String(row.key),
          request_hash: String(row.request_hash),
          response: row.response,
          created_at: new Date(String(row.created_at)).toISOString(),
        }
      : undefined
  }

  async put(
    tenantId: TenantId,
    key: string,
    requestHash: string,
    response: unknown,
  ): Promise<PostgresIdempotencyRecord> {
    const existing = await this.get(tenantId, key)
    if (existing) {
      if (existing.request_hash !== requestHash) {
        throw new IdempotencyConflictError(`Idempotency key ${key} reused with a different payload`)
      }
      return existing
    }

    const result = await this.pool.query<Row>(
      `INSERT INTO idempotency_keys
       (tenant_id, key, request_hash, response, created_at)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (tenant_id, key) DO NOTHING
       RETURNING tenant_id, key, request_hash, response, created_at`,
      [tenantId, key, requestHash, JSON.stringify(response), new Date().toISOString()],
    )

    if (result.rows[0]) {
      const row = result.rows[0]
      return {
        tenant_id: asTenantId(row.tenant_id),
        key: String(row.key),
        request_hash: String(row.request_hash),
        response: row.response,
        created_at: new Date(String(row.created_at)).toISOString(),
      }
    }

    const concurrent = await this.get(tenantId, key)
    if (!concurrent) throw new Error('Idempotency insert conflict but row was not found')
    if (concurrent.request_hash !== requestHash) {
      throw new IdempotencyConflictError(`Idempotency key ${key} reused with a different payload`)
    }
    return concurrent
  }
}

export async function withClient<T>(
  pool: Pool,
  callback: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect()
  try {
    return await callback(client)
  } finally {
    client.release()
  }
}
