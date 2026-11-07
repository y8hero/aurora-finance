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
