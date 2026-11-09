The migrations use `IF NOT EXISTS` and replace only the audit mutation
triggers. Review changes in a staging project before applying them to a
production project.

## Security model

Every table enables Row Level Security and intentionally has no policies.
That denies access to Supabase `anon` and `authenticated` roles. The Aurora
server uses the direct database connection role through `DATABASE_URL`; that
role must be protected as a server-only secret and must never be exposed to a
browser or client application.

Tenant filtering remains present in every repository query even though the
direct server role is trusted. This is defense in depth.

## Backup and recovery

Enable Supabase backups and point-in-time recovery appropriate to the
environment. Test restoration and migration replay regularly. Database
backups must be treated as sensitive because they contain raw webhook bodies,
audit metadata, tenant data, and provider identifiers.

## Still unverified

- The exact Supabase connection string format and whether the selected
  connection endpoint requires a provider-specific SSL configuration.
- Production pool sizing and operational limits.
- Supabase role configuration for the direct server connection.
- Retention, archival, and legal hold requirements for raw webhook bodies.
- Whether `gen_random_uuid()` is enabled in the target project; enable the
  required extension or replace the default before applying migration 004.
- Operational behavior and lock timing under the production workload.
- Migration deployment, backup, and restore procedures in the target Supabase
  project.


===== FILE: db/migrations/001_tenants.sql =====
CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  country text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS tenants_country_idx ON tenants (country);


===== FILE: db/migrations/002_provider_customers.sql =====
CREATE TABLE IF NOT EXISTS provider_customers (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  provider text NOT NULL,
  provider_customer_id text NOT NULL,
  kyc_tier smallint NOT NULL CHECK (kyc_tier BETWEEN 0 AND 2),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_customer_id)
);

ALTER TABLE provider_customers ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS provider_customers_tenant_idx
  ON provider_customers (tenant_id);


===== FILE: db/migrations/003_webhook_events.sql =====
CREATE TABLE IF NOT EXISTS webhook_events (
  provider text NOT NULL,
  delivery_id text NOT NULL,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  event_id text NOT NULL,
  event_type text NOT NULL,
  raw_body text NOT NULL,
  raw_body_hash text NOT NULL,
  received_at timestamptz NOT NULL,
  processed_at timestamptz,
  PRIMARY KEY (provider, delivery_id)
);

ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS webhook_events_tenant_idx
  ON webhook_events (tenant_id);
CREATE INDEX IF NOT EXISTS webhook_events_event_idx
  ON webhook_events (provider, event_id);


===== FILE: db/migrations/004_audit_log.sql =====
CREATE TABLE IF NOT EXISTS audit_log (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  seq bigint NOT NULL,
  prev_hash text NOT NULL,
  hash text NOT NULL,
  actor text NOT NULL,
  action text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, seq)
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS audit_log_tenant_created_idx
  ON audit_log (tenant_id, created_at);

CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log;
CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();


===== FILE: db/migrations/005_idempotency_keys.sql =====
CREATE TABLE IF NOT EXISTS idempotency_keys (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  key text NOT NULL,
  request_hash text NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key),
  UNIQUE (tenant_id, key)
);

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idempotency_keys_tenant_idx
  ON idempotency_keys (tenant_id);


===== FILE: src/db/pool.ts =====
import { Pool, type PoolConfig } from 'pg'
import type { AppConfig } from '../config/env'

export function createDatabasePool(config: AppConfig): Pool | undefined {
  const databaseUrl = config.DATABASE_URL

  if (!databaseUrl) return undefined

  const poolConfig: PoolConfig = {
    connectionString: databaseUrl.reveal(),
    ssl: { rejectUnauthorized: true },
    max: 10,
    min: 0,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    statement_timeout: 15_000,
    query_timeout: 15_000,
    maxUses: 10_000,
  }

  return new Pool(poolConfig)
}

export async function closeDatabasePool(pool: Pool | undefined): Promise<void> {
  if (pool) await pool.end()
}


===== FILE: src/db/repositories.ts =====
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


===== FILE: src/core/types.ts =====
/** Branded tenant identifier. Every record and every query must carry one. */
export type TenantId = string & { readonly __brand: 'TenantId' }

const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{1,63}$/i

export function tenantId(raw: string): TenantId {
  if (typeof raw !== 'string' || !TENANT_ID_PATTERN.test(raw)) {
    throw new Error(`Invalid tenant_id: ${JSON.stringify(raw)}`)
  }
  return raw as TenantId
}

/** Platform-level actions are recorded under this tenant. */
export const PLATFORM_TENANT: TenantId = tenantId('platform')

export interface TenantRecord {
  readonly tenant_id: TenantId
}

export type Region = 'EU' | 'US' | 'AFRICA'
export type ProviderName = 'maplerad' | 'circle' | 'mock'

/**
 * Monetary amounts are integer minor units represented as decimal strings.
 *
 * Examples:
 * - USD 100.00 => amount "10000", currency "USD"
 * - NGN 100.00 => amount "10000", currency "NGN"
 *
 * The `amount` property is retained for API compatibility with the Phase 1
 * skeleton; it must contain minor units, never a decimal major-unit amount.
 */
export interface Money {
  readonly amount: string
  readonly currency: string
}

export function isIntegerMinorUnitAmount(amount: string): boolean {
  return /^\d+$/.test(amount)
}

export function assertIntegerMinorUnitAmount(money: Money): void {
  if (!isIntegerMinorUnitAmount(money.amount)) {
    throw new Error(
      `Money amount must be a non-negative integer minor-unit string; received ${JSON.stringify(money.amount)}`,
    )
  }
  if (!/^[A-Z0-9]{3,10}$/.test(money.currency)) {
    throw new Error(`Invalid currency or asset code: ${JSON.stringify(money.currency)}`)
  }
}

export type Direction = 'in' | 'out'
export type ISODateTime = string


===== FILE: src/core/canonical.ts =====
/**
 * Deterministic JSON serialisation (sorted object keys) so hashes are stable
 * regardless of property insertion order.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value))
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key]
      if (v !== undefined) out[key] = sortKeys(v)
    }
    return out
  }
  return value
}


===== FILE: src/core/audit/auditLog.ts =====
import { createHash, randomUUID } from 'node:crypto'
import { canonicalJson } from '../canonical'
import type { ISODateTime, TenantId, TenantRecord } from '../types'

export interface AuditEntryInput extends TenantRecord {
  /** Who did it: user id, API key id, "system", "webhook:maplerad", ... */
  readonly actor: string
  /** Dotted verb, e.g. "webhook.stored", "payout.approved". */
  readonly action: string
  readonly before?: unknown
  readonly after?: unknown
  readonly metadata?: Readonly<Record<string, unknown>>
}

export interface AuditEntry extends AuditEntryInput {
  readonly id: string
  /** Per-tenant monotonically increasing sequence. */
  readonly seq: number
  readonly timestamp: ISODateTime
  /** Hash of the previous entry for this tenant ("GENESIS" for the first). */
  readonly prev_hash: string
  /** SHA-256 over the canonical JSON of this entry (excluding `hash`). */
  readonly hash: string
}

export interface ChainVerification {
  readonly ok: boolean
  readonly length: number
  readonly brokenAtSeq?: number
}

/**
 * Append-only audit log. There is deliberately no update or delete method.
 * Entries are hash-chained per tenant so tampering is detectable via `verify`.
 */
export interface AuditLog {
  append(input: AuditEntryInput): Promise<AuditEntry>
  list(tenantId: TenantId): Promise<readonly AuditEntry[]>
  verify(tenantId: TenantId): Promise<ChainVerification>
}

export const GENESIS_HASH = 'GENESIS'

export function hashEntry(entry: Omit<AuditEntry, 'hash'>): string {
  return createHash('sha256').update(canonicalJson(entry)).digest('hex')
}

export class InMemoryAuditLog implements AuditLog {
  private readonly chains = new Map<TenantId, AuditEntry[]>()
  private readonly now: () => Date

  constructor(now: () => Date = () => new Date()) {
    this.now = now
  }

  async append(input: AuditEntryInput): Promise<AuditEntry> {
    let chain = this.chains.get(input.tenant_id)
    if (!chain) {
      chain = []
      this.chains.set(input.tenant_id, chain)
    }
    const prev = chain[chain.length - 1]
    const unhashed: Omit<AuditEntry, 'hash'> = {
      ...input,
      id: randomUUID(),
      seq: prev ? prev.seq + 1 : 1,
      timestamp: this.now().toISOString(),
      prev_hash: prev ? prev.hash : GENESIS_HASH,
    }
    const entry: AuditEntry = Object.freeze({ ...unhashed, hash: hashEntry(unhashed) })
    chain.push(entry)
    return entry
  }

  async list(tenantId: TenantId): Promise<readonly AuditEntry[]> {
    return Object.freeze([...(this.chains.get(tenantId) ?? [])])
  }

  async verify(tenantId: TenantId): Promise<ChainVerification> {
    const chain = this.chains.get(tenantId) ?? []
    let expectedPrev = GENESIS_HASH
    for (const entry of chain) {
      const { hash, ...rest } = entry
      if (entry.prev_hash !== expectedPrev || hashEntry(rest) !== hash) {
        return { ok: false, length: chain.length, brokenAtSeq: entry.seq }
      }
      expectedPrev = hash
    }
    return { ok: true, length: chain.length }
  }

  /** TEST-ONLY hook to simulate tampering. Never present on production implementations. */
  _unsafeTamperForTests(tenantId: TenantId, seq: number, mutate: (e: AuditEntry) => AuditEntry): void {
    const chain = this.chains.get(tenantId)
    if (!chain) return
    const idx = chain.findIndex((e) => e.seq === seq)
    const existing = chain[idx]
    if (idx >= 0 && existing) chain[idx] = mutate(existing)
  }
}


===== FILE: src/core/idempotency.ts =====
import type { TenantId } from './types'

export class IdempotencyConflictError extends Error {
  override name = 'IdempotencyConflictError'
}

interface Stored<T> {
  readonly fingerprint: string
  readonly result: T
}

/**
 * Idempotency guard for money-moving calls (brief §2 rule 3, §8).
 *
 * `run(tenantId, key, fingerprint, fn)`:
 *  - first call executes `fn` and caches the result under (tenant, key)
 *  - repeat with the same fingerprint returns the cached result without re-executing
 *  - repeat with a different fingerprint throws (same key, different payload = bug or attack)
 *  - concurrent calls with the same key share the same in-flight promise
 */
export class IdempotencyStore {
  private readonly done = new Map<string, Stored<unknown>>()
  private readonly inFlight = new Map<string, Promise<unknown>>()

  async run<T>(tenantId: TenantId, key: string, fingerprint: string, fn: () => Promise<T>): Promise<T> {
    const k = `${tenantId}::${key}`
    const existing = this.done.get(k)
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw new IdempotencyConflictError(`Idempotency key ${key} reused with a different payload`)
      }
      return existing.result as T
    }
    const pending = this.inFlight.get(k)
    if (pending) return pending as Promise<T>

    const p = fn()
      .then((result) => {
        this.done.set(k, { fingerprint, result })
        return result
      })
      .finally(() => this.inFlight.delete(k))
    this.inFlight.set(k, p)
    return p
  }

  has(tenantId: TenantId, key: string): boolean {
    return this.done.has(`${tenantId}::${key}`)
  }
}


===== FILE: src/webhooks/receiver.ts =====
import { createHash } from 'node:crypto'
import type { WebhookHeaders } from '../adapters/types'
import type { AuditLog } from '../core/audit/auditLog'
import { PLATFORM_TENANT, type ProviderName, type TenantId } from '../core/types'
import type { Logger } from '../logging/logger'
import type { WebhookEventRecord, WebhookEventStore } from './eventStore'
import { headerValue, type VerifyContext, type VerifierRegistry } from './signature'

export interface WebhookParser {
  readonly provider: ProviderName
  parse(rawBody: string): {
    eventId: string
    eventType: string
    occurredAt?: string
    providerCustomerId?: string
  }
}

export interface WebhookTenantResolver {
  resolve(
    provider: ProviderName,
    providerCustomerId: string,
  ): Promise<TenantId | undefined>
}

export type ReceiveOutcome =
  | { readonly status: 'stored'; readonly record: WebhookEventRecord }
  | { readonly status: 'duplicate'; readonly record: WebhookEventRecord }
  | { readonly status: 'rejected'; readonly reason: string }

export interface ReceiveInput {
  readonly provider: ProviderName
  readonly rawBody: string
  readonly headers: WebhookHeaders
  readonly sourceIp?: string
}

export interface WebhookReceiverDeps {
  readonly verifiers: VerifierRegistry
  readonly parsers: ReadonlyMap<ProviderName, WebhookParser>
  readonly tenantResolver: WebhookTenantResolver
  readonly store: WebhookEventStore
  readonly audit: AuditLog
  readonly logger: Logger
  readonly now?: () => Date
}

export class WebhookReceiver {
  constructor(private readonly deps: WebhookReceiverDeps) {}

  async receive(input: ReceiveInput): Promise<ReceiveOutcome> {
    const verifier = this.deps.verifiers.get(input.provider)
    const parser = this.deps.parsers.get(input.provider)

    if (!verifier || !parser) {
      return this.reject(input.provider, 'no verifier/parser registered')
    }

    const verification = verifier.verify(
      input.rawBody,
      input.headers,
      input.sourceIp ? { sourceIp: input.sourceIp } : {},
    )

    if (!verification.ok) {
      return this.reject(input.provider, verification.reason ?? 'signature verification failed')
    }

    let parsed: ReturnType<WebhookParser['parse']>

    try {
      parsed = parser.parse(input.rawBody)
    } catch (error) {
      return this.reject(input.provider, `unparseable body: ${(error as Error).message}`)
    }

    if (!parsed.providerCustomerId) {
      return this.reject(input.provider, 'verified payload has no provider customer ID')
    }

    const resolvedTenant = await this.deps.tenantResolver.resolve(
      input.provider,
      parsed.providerCustomerId,
    )

    if (!resolvedTenant) {
      return this.reject(input.provider, 'provider customer is not mapped to a tenant')
    }

    const deliveryId = headerValue(input.headers, 'svix-id') ?? parsed.eventId
    const existing = await this.deps.store.findByDelivery(input.provider, deliveryId)

    if (existing && existing.tenant_id !== resolvedTenant) {
      return this.reject(
        input.provider,
        'delivery replayed for a different tenant',
      )
    }

    const now = (this.deps.now ?? (() => new Date()))()
    const record: WebhookEventRecord = {
      tenant_id: resolvedTenant,
      provider: input.provider,
      svix_id: deliveryId,
      event_id: parsed.eventId,
      event_type: parsed.eventType,
      signature_ok: true,
      raw_body_hash: createHash('sha256').update(input.rawBody).digest('hex'),
      raw_body: input.rawBody,
      received_at: now.toISOString(),
    }

    const result = await this.deps.store.insertIfAbsent(record)

    if (!result.inserted) {
      this.deps.logger.info(
        { provider: input.provider, tenantId: resolvedTenant, svixId: deliveryId },
        'webhook duplicate ignored',
      )

      await this.deps.audit.append({
        tenant_id: resolvedTenant,
        actor: `webhook:${input.provider}`,
        action: 'webhook.duplicate_ignored',
        metadata: { svixId: deliveryId, eventId: parsed.eventId },
      })

      return { status: 'duplicate', record: result.record }
    }

    await this.deps.audit.append({
      tenant_id: resolvedTenant,
      actor: `webhook:${input.provider}`,
      action: 'webhook.stored',
      after: { svixId: deliveryId, eventId: parsed.eventId },
    })

    return { status: 'stored', record: result.record }
  }

  private async reject(provider: ProviderName, reason: string): Promise<ReceiveOutcome> {
    this.deps.logger.warn({ provider, reason }, 'webhook rejected')

    await this.deps.audit.append({
      tenant_id: PLATFORM_TENANT,
      actor: `webhook:${provider}`,
      action: 'webhook.rejected',
      metadata: { reason },
    })

    return { status: 'rejected', reason }
  }
}


===== FILE: src/webhooks/eventStore.ts =====
import type { ISODateTime, ProviderName, TenantId, TenantRecord } from '../core/types'

export interface WebhookEventRecord extends TenantRecord {
  readonly provider: ProviderName
  readonly svix_id: string
  readonly event_id: string
  readonly event_type: string
  readonly signature_ok: true
  readonly raw_body_hash: string
  readonly raw_body: string
  readonly received_at: ISODateTime
  readonly processed_at?: ISODateTime
}

export interface InsertResult {
  readonly inserted: boolean
  readonly record: WebhookEventRecord
}

export interface WebhookEventStore {
  insertIfAbsent(record: WebhookEventRecord): Promise<InsertResult>
  findByDelivery(
    provider: ProviderName,
    deliveryId: string,
  ): Promise<WebhookEventRecord | undefined>
  markProcessed(
    tenantId: TenantId,
    provider: ProviderName,
    deliveryId: string,
    at: ISODateTime,
  ): Promise<void>
  list(tenantId: TenantId): Promise<readonly WebhookEventRecord[]>
}

export class InMemoryWebhookEventStore implements WebhookEventStore {
  private readonly byKey = new Map<string, WebhookEventRecord>()

  private key(tenantId: TenantId, provider: ProviderName, deliveryId: string): string {
    return `${tenantId}::${provider}::${deliveryId}`
  }

  async insertIfAbsent(record: WebhookEventRecord): Promise<InsertResult> {
    const key = this.key(record.tenant_id, record.provider, record.svix_id)
    const existing = this.byKey.get(key)

    if (existing) return { inserted: false, record: existing }

    const frozen = Object.freeze({ ...record })
    this.byKey.set(key, frozen)
    return { inserted: true, record: frozen }
  }

  async findByDelivery(
    provider: ProviderName,
    deliveryId: string,
  ): Promise<WebhookEventRecord | undefined> {
    for (const record of this.byKey.values()) {
      if (record.provider === provider && record.svix_id === deliveryId) {
        return record
      }
    }

    return undefined
  }

  async markProcessed(
    tenantId: TenantId,
    provider: ProviderName,
    deliveryId: string,
    at: ISODateTime,
  ): Promise<void> {
    const key = this.key(tenantId, provider, deliveryId)
    const existing = this.byKey.get(key)

    if (!existing) {
      throw new Error(`Webhook delivery not found for tenant ${tenantId}`)
    }

    this.byKey.set(key, Object.freeze({ ...existing, processed_at: at }))
  }

  async list(tenantId: TenantId): Promise<readonly WebhookEventRecord[]> {
    return Object.freeze(
      [...this.byKey.values()].filter((record) => record.tenant_id === tenantId),
    )
  }
}


===== FILE: src/config/env.ts =====
import { isIP } from 'node:net'
import { z } from 'zod'

const MAX_SECRET_LENGTH = 4096
const MAX_URL_LENGTH = 2048
const MAX_IP_LIST_LENGTH = 4096

export class Secret {
  readonly #value: string

  constructor(value: string) {
    this.#value = value
  }

  reveal(): string {
    return this.#value
  }

  toString(): string {
    return '[redacted]'
  }

  toJSON(): string {
    return '[redacted]'
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return '[redacted]'
  }
}

export const DEFAULT_MAPLERAD_BASE_URL = 'https://api.maplerad.com'

const optionalSecret = z
  .string()
  .trim()
  .max(MAX_SECRET_LENGTH)
  .optional()
  .transform((value) => (value && value.length > 0 ? new Secret(value) : undefined))

const optionalWhsecSecret = z
  .string()
  .trim()
  .max(MAX_SECRET_LENGTH)
  .optional()
  .refine(
    (value) => value === undefined || value.length === 0 || value.startsWith('whsec_'),
    { message: 'Maplerad webhook signing secret must start with "whsec_"' },
  )
  .transform((value) => (value && value.length > 0 ? new Secret(value) : undefined))

const optionalUrl = z
  .string()
  .trim()
  .max(MAX_URL_LENGTH)
  .optional()
  .transform((value) => (value && value.length > 0 ? value : undefined))
  .pipe(z.string().url().optional())

const mapleradBaseUrl = z
  .string()
  .trim()
  .max(MAX_URL_LENGTH)
  .optional()
  .transform((value) => (value && value.length > 0 ? value : DEFAULT_MAPLERAD_BASE_URL))
  .pipe(z.string().url().startsWith('https://', { message: 'Maplerad requires HTTPS' }))

const ipList = z
  .string()
  .trim()
  .max(MAX_IP_LIST_LENGTH)
  .optional()
  .transform((value) =>
    value
      ? value.split(',').map((part) => part.trim()).filter(Boolean)
      : [],
  )
  .refine((ips) => ips.length <= 32, {
    message: 'must contain no more than 32 IP addresses',
  })
  .refine((ips) => ips.every((ip) => isIP(ip) !== 0), {
    message: 'must be a comma-separated list of IPv4/IPv6 addresses',
  })

const schema = z.object({
  AURORA_ENV: z.enum(['development', 'test', 'sandbox']).default('development'),
  PORT: z.coerce.number().int().positive().max(65535).default(3000),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
    .default('info'),

  DATABASE_URL: optionalSecret,

  MAPLERAD_ENV: z.enum(['sandbox']).default('sandbox'),
  MAPLERAD_BASE_URL: mapleradBaseUrl,
  MAPLERAD_SECRET_KEY_SANDBOX: optionalSecret,
  MAPLERAD_WEBHOOK_SECRET: optionalWhsecSecret,
  MAPLERAD_WEBHOOK_ALLOWED_IPS: ipList,

  CIRCLE_ENV: z.enum(['testnet']).default('testnet'),
  CIRCLE_API_KEY_TESTNET: optionalSecret,
  CIRCLE_API_KEY_MAINNET: optionalSecret,
  CIRCLE_BASE_URL_TESTNET: optionalUrl,
  CIRCLE_BASE_URL_MAINNET: optionalUrl,

  MOCK_WEBHOOK_SECRET: z
    .string()
    .min(8)
    .max(MAX_SECRET_LENGTH)
    .default('dev-only-mock-secret-change-me'),
}).strict()

export type AppConfig = Readonly<z.infer<typeof schema>>

export class ConfigError extends Error {
  override name = 'ConfigError'
}

function nonEmpty(value: string | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0
}

function removeEmptyLegacyMapleradKeys(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const sanitized = { ...env }

  for (const key of ['MAPLERAD_SECRET_KEY_LIVE', 'MAPLERAD_SECRET_KEY'] as const) {
    if (typeof sanitized[key] === 'string' && sanitized[key].trim().length === 0) {
      delete sanitized[key]
    }
  }

  return sanitized
}

const CONFIG_KEYS = [
  'AURORA_ENV',
  'PORT',
  'LOG_LEVEL',
  'DATABASE_URL',
  'MAPLERAD_ENV',
  'MAPLERAD_BASE_URL',
  'MAPLERAD_SECRET_KEY_SANDBOX',
  'MAPLERAD_WEBHOOK_SECRET',
  'MAPLERAD_WEBHOOK_ALLOWED_IPS',
  'CIRCLE_ENV',
  'CIRCLE_API_KEY_TESTNET',
  'CIRCLE_API_KEY_MAINNET',
  'CIRCLE_BASE_URL_TESTNET',
  'CIRCLE_BASE_URL_MAINNET',
  'MOCK_WEBHOOK_SECRET',
] as const

function selectConfigEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const selected: NodeJS.ProcessEnv = {}

  for (const key of CONFIG_KEYS) {
    if (env[key] !== undefined) selected[key] = env[key]
  }

  return selected
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  if (env.AURORA_ENV === 'production') {
    throw new ConfigError(
      'Phase 1 skeleton refuses AURORA_ENV=production. No production until Phase 4+ and legal sign-off.',
    )
  }

  if (env.MAPLERAD_ENV === 'live') {
    throw new ConfigError('Phase 1 skeleton refuses MAPLERAD_ENV=live. Sandbox only.')
  }

  if (nonEmpty(env.MAPLERAD_SECRET_KEY_LIVE)) {
    throw new ConfigError(
      'Phase 1 skeleton refuses a Maplerad LIVE key (MAPLERAD_SECRET_KEY_LIVE).',
    )
  }

  if (nonEmpty(env.MAPLERAD_SECRET_KEY)) {
    throw new ConfigError(
      'MAPLERAD_SECRET_KEY was renamed to MAPLERAD_SECRET_KEY_SANDBOX. Update .env.',
    )
  }

  if (env.CIRCLE_ENV === 'mainnet') {
    throw new ConfigError('Phase 1 skeleton refuses CIRCLE_ENV=mainnet. Testnet only.')
  }

  const parsed = schema.safeParse(selectConfigEnvironment(removeEmptyLegacyMapleradKeys(env)))

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ')
    throw new ConfigError(`Invalid configuration: ${issues}`)
  }

  return Object.freeze(parsed.data)
}


===== FILE: src/server.ts =====
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { loadConfig } from './config/env'
import { createLogger } from './logging/logger'
import { InMemoryAuditLog } from './core/audit/auditLog'
import { tenantId, type ProviderName } from './core/types'
import { MockAdapter, mockWebhookParser } from './adapters/mock/MockAdapter'
import { MapleradAdapter } from './adapters/maplerad/MapleradAdapter'
import { CircleAdapter } from './adapters/circle/CircleAdapter'
import { InMemoryWebhookEventStore } from './webhooks/eventStore'
import { VerifierRegistry } from './webhooks/signature'
import { WebhookReceiver, type WebhookParser, type WebhookTenantResolver } from './webhooks/receiver'

const config = loadConfig()
const logger = createLogger(config.LOG_LEVEL)
const audit = new InMemoryAuditLog()
const eventStore = new InMemoryWebhookEventStore()

const mock = new MockAdapter(config.MOCK_WEBHOOK_SECRET)
const maplerad = new MapleradAdapter({
  environment: config.MAPLERAD_ENV,
  baseUrl: config.MAPLERAD_BASE_URL,
  secretKey: config.MAPLERAD_SECRET_KEY_SANDBOX,
  webhookSecret: config.MAPLERAD_WEBHOOK_SECRET,
  allowedWebhookIps: config.MAPLERAD_WEBHOOK_ALLOWED_IPS,
})
const circle = new CircleAdapter({
  environment: config.CIRCLE_ENV,
  apiKey: config.CIRCLE_API_KEY_TESTNET,
  baseUrl: config.CIRCLE_BASE_URL_TESTNET,
})

const verifiers = new VerifierRegistry().register(mock.verifier)
if (maplerad.webhookVerifier) verifiers.register(maplerad.webhookVerifier)

const parsers = new Map<ProviderName, WebhookParser>([['mock', mockWebhookParser]])
const tenantResolver: WebhookTenantResolver = mock.tenantResolver
const receiver = new WebhookReceiver({
  verifiers,
  parsers,
  tenantResolver,
  store: eventStore,
  audit,
  logger,
})

const PROVIDERS: ReadonlySet<string> = new Set<ProviderName>(['maplerad', 'circle', 'mock'])
const MAX_BODY_BYTES = 1_000_000

function readBody(req: IncomingMessage): Promise<string> {
  const declaredLength = req.headers['content-length']

  if (declaredLength !== undefined) {
    const length = Number(declaredLength)
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_BODY_BYTES) {
      return Promise.reject(new Error('request body exceeds the 1 MB limit'))
    }
  }

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    let settled = false

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      reject(error)
      req.destroy()
    }

    req.on('data', (chunk: Buffer) => {
      if (settled) return
      size += chunk.length

      if (size > MAX_BODY_BYTES) {
        fail(new Error('request body exceeds the 1 MB limit'))
        return
      }

      chunks.push(chunk)
    })

    req.on('end', () => {
      if (!settled) {
        settled = true
        resolve(Buffer.concat(chunks).toString('utf8'))
      }
    })

    req.on('error', (error) => {
      fail(error instanceof Error ? error : new Error(String(error)))
    })
  })
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const encoded = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(encoded),
  })
  res.end(encoded)
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost')

  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, {
      ok: true,
      phase: 1,
      env: config.AURORA_ENV,
      adapters: {
        mock: 'active',
        maplerad: {
          environment: maplerad.environment,
          baseUrl: maplerad.baseUrl,
          status: 'stub — no live calls',
          secretConfigured: maplerad.hasSecretKey,
        },
        circle: {
          environment: circle.environment,
          status: 'UNVERIFIED stub',
          apiKeyConfigured: circle.hasApiKey,
        },
      },
    })
  }

  const match = url.pathname.match(/^\/webhooks\/([a-z]+)(?:\/[A-Za-z0-9_-]+)?$/)

  if (req.method === 'POST' && match) {
    const providerRaw = match[1]

    if (!providerRaw || !PROVIDERS.has(providerRaw)) {
      return json(res, 404, { error: 'not found' })
    }

    const provider = providerRaw as ProviderName

    try {
      const rawBody = await readBody(req)
      const headers = Object.fromEntries(
        Object.entries(req.headers).map(([key, value]) => [key.toLowerCase(), value]),
      )

      if (provider !== 'mock') {
        logger.warn({ provider }, 'provider webhook route is unverified')
        return json(res, 501, { error: 'provider webhook unavailable' })
      }

      const outcome = await receiver.receive({
        provider,
        rawBody,
        headers,
        ...(req.socket.remoteAddress ? { sourceIp: req.socket.remoteAddress } : {}),
      })

      if (outcome.status === 'rejected') {
        logger.warn({ provider, reason: outcome.reason }, 'webhook rejected')
        return json(res, 401, { error: 'unauthorized' })
      }

      return json(res, 200, {
        status: outcome.status,
        svixId: outcome.record.svix_id,
        eventId: outcome.record.event_id,
        tenantId: outcome.record.tenant_id,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)

      if (message === 'request body exceeds the 1 MB limit') {
        logger.warn({ provider }, 'request body too large')
        return json(res, 413, { error: 'request too large' })
      }

      logger.error({ err: error, provider }, 'internal webhook error')
      return json(res, 500, { error: 'internal server error' })
    }
  }

  return json(res, 404, { error: 'not found' })
})

server.listen(config.PORT, () => {
  logger.info(
    { port: config.PORT, env: config.AURORA_ENV },
    'Aurora Core Phase 1 skeleton listening. Only mock is active; Maplerad/Circle make no calls.',
  )
})
AURORA CORE SNAPSHOT (commit d420127). Secrets excluded; .env never included.


===== FILE: package.json =====
{
  "name": "aurora-core",
  "version": "0.1.0",
  "private": true,
  "description": "Aurora money layer - Phase 2 step 1 persistence foundation",
  "type": "module",
  "engines": {
    "node": ">=18"
  },
  "scripts": {
    "dev": "tsx --env-file=.env watch src/server.ts",
    "start": "tsx --env-file=.env src/server.ts",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "probe:maplerad": "tsx --env-file=.env scripts/probe-maplerad.ts",
    "probe:circle": "tsx --env-file=.env scripts/probe-circle.ts"
  },
  "dependencies": {
    "pg": "^8.13.1",
    "pino": "^9.5.0",
    "zod": "^4.6.7"
  },
  "devDependencies": {
    "@types/node": "^22.9.0",
    "@types/pg": "^8.11.10",
    "tsx": "^4.19.2",
    "typescript": "^5.6.3",
    "vitest": "^2.1.5"
  }
}


===== FILE: tsconfig.json =====
Also provide the current file list under:


===== FILE: .gitignore =====
node_modules
dist
.env
.env.*
!.env.example
*.log


===== FILE: .env.example =====
# Aurora Core - Phase 1 skeleton
# Copy to .env and fill in. NEVER commit .env. NEVER put real values in docs or chat.

# development | test | sandbox   ("production" is refused in Phase 1)
AURORA_ENV=development
PORT=3000
LOG_LEVEL=info

# --- Maplerad ---
# VERIFIED (maplerad.dev/docs/environment): ONE base URL for sandbox AND live. The KEY decides the environment.
MAPLERAD_BASE_URL=https://api.maplerad.com
# Which key slot Aurora uses. Only "sandbox" is accepted in Phase 0-3.
MAPLERAD_ENV=sandbox
# Sandbox secret key from the Sandbox Dashboard (app.maplerad.com, switch to sandbox account). Server-side only.
MAPLERAD_SECRET_KEY_SANDBOX=
# MAPLERAD_SECRET_KEY_LIVE is REFUSED by the config loader in Phase 0-3. Do not set it anywhere yet.
# Webhook signing secret from the business dashboard. VERIFIED scheme is Svix-style; the value starts with "whsec_".
MAPLERAD_WEBHOOK_SECRET=
# Optional: comma-separated webhook source IPs copied from https://maplerad.dev/docs/verifying-webhooks (ten addresses).
# Copy them from the page; do not guess. Empty = no IP filter.
MAPLERAD_WEBHOOK_ALLOWED_IPS=

# --- Circle (testnet only in Phase 1; "mainnet" is refused) ---
# Testnet and mainnet use SEPARATE keys and may use different base URLs.
CIRCLE_ENV=testnet
CIRCLE_API_KEY_TESTNET=
CIRCLE_API_KEY_MAINNET=
# UNVERIFIED: confirm from Circle MCP / docs before use.
CIRCLE_BASE_URL_TESTNET=
CIRCLE_BASE_URL_MAINNET=

# --- Mock provider (tests and local dev only) ---
MOCK_WEBHOOK_SECRET=dev-only-mock-secret-change-me


===== FILE: README.md =====
# Aurora Core — Phase 1 skeleton

Provider-agnostic foundation for the Aurora money layer. **No real provider calls exist in this phase.**

## Phase 0 facts applied

- Maplerad uses one HTTPS base URL: `https://api.maplerad.com`; the key decides sandbox/live.
- Maplerad authentication is `Authorization: Bearer <SECRET_KEY>`.
- Maplerad Svix-style webhook signatures are implemented with raw-body signing, Base64 HMAC-SHA256, `whsec_` decoding, five-minute timestamp tolerance, optional IP filtering, and `svix-id` deduplication.
- Maplerad restricted jurisdictions are stored in `src/config/restricted-jurisdictions.json`, with `last_checked: 2026-11-07`.
- Tenant countries, UBO countries, and counterparty countries can be screened before onboarding or payout workflows.
- Money amounts are integer minor-unit strings. Floats and major-unit decimal strings are rejected by `assertIntegerMinorUnitAmount`.
- Reconciliation is modeled as a polling backup. It reports provider-versus-ledger differences and does not credit value from a webhook alone.

## Still unverified

- Maplerad supported countries/currencies per product.
- Exact response schemas, rate limits, and error formats.
- Maplerad webhook event names and payloads.
- `maplerad-node` sandbox behavior.
- Solana support per asset on Maplerad and Circle.
- Circle wallet product and third-party tenant permissions.
- Apple Pay / Google Pay provisioning.
- Maplerad BaaS white-label terms.

## Run
