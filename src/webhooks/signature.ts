import { createHmac, timingSafeEqual } from 'node:crypto'
import type { ProviderName } from '../core/types'
import type { WebhookHeaders } from '../adapters/types'

export interface VerificationResult {
  readonly ok: boolean
  readonly reason?: string
  /** Unix seconds from the signed timestamp header, when present. */
  readonly signedAt?: number
}

/** Transport-level facts a verifier may use in addition to body + headers. */
export interface VerifyContext {
  /** Remote address of the sender, when known. Used for provider IP allow-lists. */
  readonly sourceIp?: string
}

/** Pluggable per-provider signature verifier. */
export interface SignatureVerifier {
  readonly provider: ProviderName
  verify(rawBody: string, headers: WebhookHeaders, context?: VerifyContext): VerificationResult
}

export interface HmacSha256Options {
  readonly provider: ProviderName
  readonly secret: string
  /** Header carrying the signature (lower-case). */
  readonly signatureHeader: string
  /** Optional header carrying a unix-seconds timestamp; enables stale-timestamp rejection. */
  readonly timestampHeader?: string
  readonly toleranceSeconds?: number
  readonly encoding?: 'hex' | 'base64'
  /** How to build the signed payload. Default: `${ts}.${body}` if a timestamp header is used, else body. */
  readonly signedPayload?: (body: string, timestamp: string | undefined) => string
  readonly now?: () => number
}

export function headerValue(headers: WebhookHeaders, name: string): string | undefined {
  const v = headers[name.toLowerCase()] ?? headers[name]
  return Array.isArray(v) ? v[0] : v
}

/**
 * Generic HMAC-SHA256 verifier with constant-time comparison and timestamp tolerance.
 * Used by the mock provider only. Maplerad has its own Svix-style verifier
 * (src/adapters/maplerad/MapleradWebhookVerifier.ts); Circle's scheme is still UNVERIFIED.
 */
export class HmacSha256Verifier implements SignatureVerifier {
  readonly provider: ProviderName
  private readonly opts: Required<Omit<HmacSha256Options, 'timestampHeader' | 'provider'>> & {
    timestampHeader?: string
  }

  constructor(options: HmacSha256Options) {
    this.provider = options.provider
    const encoding = options.encoding ?? 'hex'
    this.opts = {
      secret: options.secret,
      signatureHeader: options.signatureHeader.toLowerCase(),
      toleranceSeconds: options.toleranceSeconds ?? 300,
      encoding,
      signedPayload:
        options.signedPayload ?? ((body, ts) => (ts === undefined ? body : `${ts}.${body}`)),
      now: options.now ?? (() => Math.floor(Date.now() / 1000)),
    }
    if (options.timestampHeader) this.opts.timestampHeader = options.timestampHeader.toLowerCase()
  }

  sign(rawBody: string, timestamp?: string): string {
    const payload = this.opts.signedPayload(rawBody, timestamp)
    return createHmac('sha256', this.opts.secret).update(payload).digest(this.opts.encoding)
  }

  verify(rawBody: string, headers: WebhookHeaders, _context?: VerifyContext): VerificationResult {
    const provided = headerValue(headers, this.opts.signatureHeader)
    if (!provided) return { ok: false, reason: `missing ${this.opts.signatureHeader} header` }

    let timestamp: string | undefined
    let signedAt: number | undefined
    if (this.opts.timestampHeader) {
      timestamp = headerValue(headers, this.opts.timestampHeader)
      if (!timestamp) return { ok: false, reason: `missing ${this.opts.timestampHeader} header` }
      signedAt = Number(timestamp)
      if (!Number.isFinite(signedAt)) return { ok: false, reason: 'timestamp not numeric' }
      if (Math.abs(this.opts.now() - signedAt) > this.opts.toleranceSeconds) {
        return { ok: false, reason: 'timestamp outside tolerance (possible replay)', signedAt }
      }
    }

    const expected = this.sign(rawBody, timestamp)
    const a = Buffer.from(expected)
    const b = Buffer.from(provided)
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return signedAt === undefined
        ? { ok: false, reason: 'signature mismatch' }
        : { ok: false, reason: 'signature mismatch', signedAt }
    }
    return signedAt === undefined ? { ok: true } : { ok: true, signedAt }
  }
}

export class VerifierRegistry {
  private readonly verifiers = new Map<ProviderName, SignatureVerifier>()

  register(verifier: SignatureVerifier): this {
    this.verifiers.set(verifier.provider, verifier)
    return this
  }

  get(provider: ProviderName): SignatureVerifier | undefined {
    return this.verifiers.get(provider)
  }

  has(provider: ProviderName): boolean {
    return this.verifiers.has(provider)
  }
}
