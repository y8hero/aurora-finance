import { createHmac, timingSafeEqual } from 'node:crypto'
import { isIP } from 'node:net'
import { Secret } from '../../config/env'
import type { WebhookHeaders } from '../types'
import { headerValue, type SignatureVerifier, type VerificationResult, type VerifyContext } from '../../webhooks/signature'

/**
 * Maplerad webhook signature verification.
 * VERIFIED from https://maplerad.dev/docs/verifying-webhooks (2026-11-07):
 *
 *  - Headers: `svix-id`, `svix-timestamp` (seconds since epoch), `svix-signature`
 *    (space-delimited entries like `v1,<base64sig>`).
 *  - Signed content: `{svix-id}.{svix-timestamp}.{raw body}` — raw body, before any parsing.
 *  - Key: signing secret starts with `whsec_`. Strip the prefix, Base64-decode the rest, use as HMAC key.
 *  - Signature: HMAC-SHA256 of the signed content, Base64-encoded. Match any `v1` entry, constant-time.
 *  - Timestamp tolerance: docs give no value; Aurora uses 5 minutes.
 *  - Optionally restrict to Maplerad's published webhook IPs (copied from the docs page, never guessed).
 *  - The docs' Go sample (hex + re-serialised JSON) is wrong and is deliberately NOT followed.
 */
export const MAPLERAD_SVIX_ID_HEADER = 'svix-id'
export const MAPLERAD_SVIX_TIMESTAMP_HEADER = 'svix-timestamp'
export const MAPLERAD_SVIX_SIGNATURE_HEADER = 'svix-signature'
export const MAPLERAD_WEBHOOK_SECRET_PREFIX = 'whsec_'
export const MAPLERAD_WEBHOOK_SIGNATURE_VERSION = 'v1'
export const MAPLERAD_WEBHOOK_DEFAULT_TOLERANCE_SECONDS = 300

export class MapleradWebhookSecretError extends Error {
  override name = 'MapleradWebhookSecretError'
}

/** `whsec_<base64>` -> raw HMAC key bytes. */
export function decodeMapleradSigningSecret(secret: string): Buffer {
  if (!secret.startsWith(MAPLERAD_WEBHOOK_SECRET_PREFIX)) {
    throw new MapleradWebhookSecretError(`Maplerad webhook secret must start with "${MAPLERAD_WEBHOOK_SECRET_PREFIX}"`)
  }
  const encoded = secret.slice(MAPLERAD_WEBHOOK_SECRET_PREFIX.length)
  const key = Buffer.from(encoded, 'base64')
  if (key.length === 0) {
    throw new MapleradWebhookSecretError('Maplerad webhook secret has no key material after the whsec_ prefix')
  }
  return key
}

export function mapleradSignedContent(svixId: string, svixTimestamp: string, rawBody: string): string {
  return `${svixId}.${svixTimestamp}.${rawBody}`
}

/** Base64 HMAC-SHA256 over the signed content. */
export function computeMapleradSignature(key: Buffer, svixId: string, svixTimestamp: string, rawBody: string): string {
  return createHmac('sha256', key).update(mapleradSignedContent(svixId, svixTimestamp, rawBody), 'utf8').digest('base64')
}

/** Returns the base64 parts of every `v1,<sig>` entry in a space-delimited svix-signature header. */
export function parseSvixSignatureHeader(value: string): readonly string[] {
  const out: string[] = []
  for (const entry of value.split(/\s+/)) {
    if (!entry) continue
    const comma = entry.indexOf(',')
    if (comma < 0) continue
    const version = entry.slice(0, comma)
    const sig = entry.slice(comma + 1)
    if (version === MAPLERAD_WEBHOOK_SIGNATURE_VERSION && sig.length > 0) out.push(sig)
  }
  return out
}

/** Strips the IPv4-mapped IPv6 prefix Node reports for IPv4 peers on dual-stack sockets. */
export function normaliseIp(ip: string): string {
  const trimmed = ip.trim()
  if (trimmed.startsWith('::ffff:')) {
    const v4 = trimmed.slice('::ffff:'.length)
    if (isIP(v4) === 4) return v4
  }
  return trimmed
}

export interface MapleradWebhookVerifierOptions {
  readonly signingSecret: Secret | string
  readonly toleranceSeconds?: number
  /** Published Maplerad webhook IPs, copied from the docs. Empty = no IP filtering. */
  readonly allowedSourceIps?: readonly string[]
  /** Unix seconds; injectable for tests. */
  readonly now?: () => number
}

export class MapleradWebhookVerifier implements SignatureVerifier {
  readonly provider = 'maplerad' as const
  readonly toleranceSeconds: number
  readonly allowedSourceIps: readonly string[]
  readonly #key: Buffer
  readonly #now: () => number

  constructor(options: MapleradWebhookVerifierOptions) {
    const raw = options.signingSecret instanceof Secret ? options.signingSecret.reveal() : options.signingSecret
    this.#key = decodeMapleradSigningSecret(raw)
    this.toleranceSeconds = options.toleranceSeconds ?? MAPLERAD_WEBHOOK_DEFAULT_TOLERANCE_SECONDS
    this.allowedSourceIps = Object.freeze((options.allowedSourceIps ?? []).map(normaliseIp))
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000))
  }

  verify(rawBody: string, headers: WebhookHeaders, context: VerifyContext = {}): VerificationResult {
    if (this.allowedSourceIps.length > 0) {
      if (!context.sourceIp) return { ok: false, reason: 'source IP unknown but Maplerad IP allow-list is configured' }
      if (!this.allowedSourceIps.includes(normaliseIp(context.sourceIp))) {
        return { ok: false, reason: 'source IP not in Maplerad allow-list' }
      }
    }

    const svixId = headerValue(headers, MAPLERAD_SVIX_ID_HEADER)
    if (!svixId) return { ok: false, reason: `missing ${MAPLERAD_SVIX_ID_HEADER} header` }
    const svixTimestamp = headerValue(headers, MAPLERAD_SVIX_TIMESTAMP_HEADER)
    if (!svixTimestamp) return { ok: false, reason: `missing ${MAPLERAD_SVIX_TIMESTAMP_HEADER} header` }
    const signatureHeader = headerValue(headers, MAPLERAD_SVIX_SIGNATURE_HEADER)
    if (!signatureHeader) return { ok: false, reason: `missing ${MAPLERAD_SVIX_SIGNATURE_HEADER} header` }

    if (!/^\d+$/.test(svixTimestamp)) return { ok: false, reason: 'svix-timestamp is not an integer' }
    const signedAt = Number(svixTimestamp)
    if (Math.abs(this.#now() - signedAt) > this.toleranceSeconds) {
      return { ok: false, reason: 'svix-timestamp outside tolerance (possible replay)', signedAt }
    }

    const candidates = parseSvixSignatureHeader(signatureHeader)
    if (candidates.length === 0) return { ok: false, reason: 'no v1 entry in svix-signature', signedAt }

    const expected = Buffer.from(computeMapleradSignature(this.#key, svixId, svixTimestamp, rawBody), 'base64')
    for (const candidate of candidates) {
      const provided = Buffer.from(candidate, 'base64')
      if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
        return { ok: true, signedAt }
      }
    }
    return { ok: false, reason: 'signature mismatch', signedAt }
  }

  /** Produces a full `svix-signature` header value. For tests and the mock relay only. */
  sign(rawBody: string, svixId: string, svixTimestamp: string): string {
    return `${MAPLERAD_WEBHOOK_SIGNATURE_VERSION},${computeMapleradSignature(this.#key, svixId, svixTimestamp, rawBody)}`
  }

  toJSON(): Record<string, unknown> {
    return {
      provider: this.provider,
      toleranceSeconds: this.toleranceSeconds,
      allowedSourceIps: this.allowedSourceIps,
      key: '[redacted]',
    }
  }
}
