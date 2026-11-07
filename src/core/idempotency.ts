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
