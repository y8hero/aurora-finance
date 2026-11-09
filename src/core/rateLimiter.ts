export interface RateLimitResult {
  readonly allowed: boolean
  readonly remaining: number
  readonly retryAfterSeconds: number
}

interface Bucket {
  tokens: number
  updatedAt: number
}

export class TokenBucketRateLimiter {
  private readonly buckets = new Map<string, Bucket>()

  constructor(
    private readonly capacity: number,
    private readonly refillPerSecond: number,
    private readonly now: () => number = () => Date.now(),
  ) {
    if (!Number.isFinite(capacity) || capacity <= 0) throw new Error('capacity must be positive')
    if (!Number.isFinite(refillPerSecond) || refillPerSecond <= 0) throw new Error('refill rate must be positive')
  }

  consume(key: string, tokens = 1): RateLimitResult {
    if (!Number.isFinite(tokens) || tokens <= 0) throw new Error('tokens must be positive')
    const current = this.now()
    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, updatedAt: current }
    const elapsed = Math.max(0, current - bucket.updatedAt) / 1000
    bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsed * this.refillPerSecond)
    bucket.updatedAt = current

    if (bucket.tokens < tokens) {
      this.buckets.set(key, bucket)
      return {
        allowed: false,
        remaining: Math.floor(bucket.tokens),
        retryAfterSeconds: Math.max(1, Math.ceil((tokens - bucket.tokens) / this.refillPerSecond)),
      }
    }

    bucket.tokens -= tokens
    this.buckets.set(key, bucket)
    return { allowed: true, remaining: Math.floor(bucket.tokens), retryAfterSeconds: 0 }
  }

  clear(key?: string): void {
    if (key) this.buckets.delete(key)
    else this.buckets.clear()
  }
}
