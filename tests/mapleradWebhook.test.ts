import { createHmac } from 'node:crypto'
import pino from 'pino'
import { describe, expect, it } from 'vitest'
import {
  MapleradWebhookSecretError,
  MapleradWebhookVerifier,
  decodeMapleradSigningSecret,
  normaliseIp,
  parseSvixSignatureHeader,
} from '../src/adapters/maplerad/MapleradWebhookVerifier'
import { Secret } from '../src/config/env'
import { InMemoryAuditLog } from '../src/core/audit/auditLog'
import { PLATFORM_TENANT, type ProviderName } from '../src/core/types'
import { InMemoryWebhookEventStore } from '../src/webhooks/eventStore'
import { WebhookReceiver, type WebhookParser } from '../src/webhooks/receiver'
import { VerifierRegistry } from '../src/webhooks/signature'

/**
 * Known-good vector, generated here with node:crypto INDEPENDENTLY of the verifier module:
 *   key      = utf8 bytes of RAW_KEY_TEXT
 *   secret   = "whsec_" + base64(key)
 *   content  = `${svix-id}.${svix-timestamp}.${raw body}`
 *   sig      = base64(HMAC-SHA256(key, content))
 */
const RAW_KEY_TEXT = 'aurora-test-signing-key-0123456789'
const RAW_KEY = Buffer.from(RAW_KEY_TEXT, 'utf8')
const SECRET = `whsec_${RAW_KEY.toString('base64')}`
const NOW = Math.floor(Date.UTC(2026, 10, 7, 12, 0, 0) / 1000)
const SVIX_ID = 'msg_aurora_vector_0001'
const SVIX_TS = String(NOW)
const BODY = '{"event":"test.vector","data":{"amount":"100.00","currency":"NGN","nested":{"b":2,"a":1}}}'

function referenceSignature(key: Buffer, id: string, ts: string, body: string): string {
  return createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64')
}

const REF_SIG = referenceSignature(RAW_KEY, SVIX_ID, SVIX_TS, BODY)

function headers(overrides: Record<string, string | undefined> = {}) {
  const base: Record<string, string | undefined> = {
    'svix-id': SVIX_ID,
    'svix-timestamp': SVIX_TS,
    'svix-signature': `v1,${REF_SIG}`,
    'content-type': 'application/json',
    ...overrides,
  }
  return base
}

function makeVerifier(
  opts: Partial<ConstructorParameters<typeof MapleradWebhookVerifier>[0]> = {},
) {
  return new MapleradWebhookVerifier({ signingSecret: SECRET, now: () => NOW, ...opts })
}

describe('Maplerad Svix-style signature: helpers', () => {
  it('decodes whsec_ secrets to the raw key', () => {
    expect(decodeMapleradSigningSecret(SECRET).equals(RAW_KEY)).toBe(true)
    expect(() => decodeMapleradSigningSecret('nope_abc')).toThrow(MapleradWebhookSecretError)
    expect(() => decodeMapleradSigningSecret('whsec_')).toThrow(MapleradWebhookSecretError)
  })

  it('extracts only v1 entries from a space-delimited header', () => {
    expect(parseSvixSignatureHeader(`v1,${REF_SIG}`)).toEqual([REF_SIG])
    expect(parseSvixSignatureHeader(`v0,aaaa v1,bbbb  v1,cccc`)).toEqual(['bbbb', 'cccc'])
    expect(parseSvixSignatureHeader('v0,aaaa')).toEqual([])
    expect(parseSvixSignatureHeader('garbage')).toEqual([])
  })

  it('normalises IPv4-mapped IPv6 addresses', () => {
    expect(normaliseIp('::ffff:203.0.113.10')).toBe('203.0.113.10')
    expect(normaliseIp('203.0.113.10')).toBe('203.0.113.10')
    expect(normaliseIp('2001:db8::1')).toBe('2001:db8::1')
  })
})

describe('MapleradWebhookVerifier', () => {
  it('accepts the independently computed known-good vector', () => {
    const v = makeVerifier()
    expect(v.verify(BODY, headers())).toEqual({ ok: true, signedAt: NOW })
  })

  it('its own sign() reproduces the reference vector exactly', () => {
    const v = makeVerifier()
    expect(v.sign(BODY, SVIX_ID, SVIX_TS)).toBe(`v1,${REF_SIG}`)
  })

  it('accepts a Secret-wrapped signing secret', () => {
    const v = new MapleradWebhookVerifier({
      signingSecret: new Secret(SECRET),
      now: () => NOW,
    })
    expect(v.verify(BODY, headers()).ok).toBe(true)
  })

  it('accepts when the valid v1 entry is one of several (including unknown versions)', () => {
    const v = makeVerifier()
    const bogus = Buffer.alloc(32, 7).toString('base64')
    const h = headers({
      'svix-signature': `v0,deadbeef v1,${bogus} v1,${REF_SIG}`,
    })
    expect(v.verify(BODY, h).ok).toBe(true)
  })

  it('rejects when only non-v1 entries are present', () => {
    const v = makeVerifier()
    const out = v.verify(BODY, headers({ 'svix-signature': `v0,${REF_SIG}` }))
    expect(out.ok).toBe(false)
    expect(out.reason).toMatch(/no v1/)
  })

  it('rejects a wrong secret', () => {
    const other = `whsec_${Buffer.from('some-other-key-xxxxxxxxxxxxxxxxxxxx').toString('base64')}`
    const v = new MapleradWebhookVerifier({
      signingSecret: other,
      now: () => NOW,
    })
    expect(v.verify(BODY, headers())).toMatchObject({
      ok: false,
      reason: 'signature mismatch',
    })
  })

  it('rejects a tampered body (signed content uses the RAW body)', () => {
    const v = makeVerifier()
    expect(v.verify(BODY.replace('100.00', '999999.00'), headers()).ok).toBe(false)

    const reordered =
      '{"event":"test.vector","data":{"amount":"100.00","currency":"NGN","nested":{"a":1,"b":2}}}'
    expect(v.verify(reordered, headers()).ok).toBe(false)
  })

  it('rejects a changed svix-id or svix-timestamp (both are part of the signed content)', () => {
    const v = makeVerifier()
    expect(v.verify(BODY, headers({ 'svix-id': 'msg_other' })).ok).toBe(false)
    expect(v.verify(BODY, headers({ 'svix-timestamp': String(NOW - 1) })).ok).toBe(false)
  })

  it('rejects stale and future timestamps beyond 5 minutes, accepts within', () => {
    const verifyAt = (timestamp: number) => {
      const value = String(timestamp)
      const signature = referenceSignature(RAW_KEY, SVIX_ID, value, BODY)
      return makeVerifier().verify(
        BODY,
        headers({
          'svix-timestamp': value,
          'svix-signature': `v1,${signature}`,
        }),
      )
    }

    expect(verifyAt(NOW - 300).ok).toBe(true)
    expect(verifyAt(NOW + 300).ok).toBe(true)
    expect(verifyAt(NOW - 301)).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/replay|tolerance/),
    })
    expect(verifyAt(NOW + 301).ok).toBe(false)
    expect(verifyAt(NOW - 3600).ok).toBe(false)
  })

  it('rejects missing or malformed headers', () => {
    const v = makeVerifier()
    expect(v.verify(BODY, headers({ 'svix-id': undefined })).reason).toMatch(/svix-id/)
    expect(v.verify(BODY, headers({ 'svix-timestamp': undefined })).reason).toMatch(/svix-timestamp/)
    expect(v.verify(BODY, headers({ 'svix-signature': undefined })).reason).toMatch(/svix-signature/)
    expect(v.verify(BODY, headers({ 'svix-timestamp': '12ab' })).reason).toMatch(/integer/)
    expect(v.verify(BODY, headers({ 'svix-signature': 'v1,!!!not-base64-of-32-bytes' })).ok).toBe(false)
    expect(v.verify(BODY, {}).ok).toBe(false)
  })

  it('refuses secrets that do not start with whsec_', () => {
    expect(() =>
      new MapleradWebhookVerifier({
        signingSecret: 'sk_test_not_a_webhook_secret',
      }),
    ).toThrow(MapleradWebhookSecretError)
  })

  it('never exposes the key material', () => {
    const v = makeVerifier()
    const dumped = JSON.stringify(v)
    expect(dumped).not.toContain(RAW_KEY.toString('base64'))
    expect(dumped).not.toContain(RAW_KEY_TEXT)
    expect(dumped).toContain('[redacted]')
  })

  describe('IP allow-list', () => {
    const allowed = ['203.0.113.10', '2001:db8::1']

    it('is a no-op when empty', () => {
      expect(
        makeVerifier().verify(BODY, headers(), { sourceIp: '198.51.100.1' }).ok,
      ).toBe(true)
    })

    it('accepts listed IPs, including IPv4-mapped form', () => {
      const v = makeVerifier({ allowedSourceIps: allowed })
      expect(v.verify(BODY, headers(), { sourceIp: '203.0.113.10' }).ok).toBe(true)
      expect(v.verify(BODY, headers(), { sourceIp: '::ffff:203.0.113.10' }).ok).toBe(true)
      expect(v.verify(BODY, headers(), { sourceIp: '2001:db8::1' }).ok).toBe(true)
    })

    it('rejects unlisted or unknown IPs before touching the signature', () => {
      const v = makeVerifier({ allowedSourceIps: allowed })
      expect(v.verify(BODY, headers(), { sourceIp: '198.51.100.1' })).toMatchObject({
        ok: false,
        reason: expect.stringMatching(/allow-list/),
      })
      expect(v.verify(BODY, headers())).toMatchObject({
        ok: false,
        reason: expect.stringMatching(/unknown/),
      })
    })
  })
})

describe('maplerad verifier in the receiver pipeline', () => {
  it('registers under provider "maplerad" and rejects an unresolved event in system scope', async () => {
    const verifiers = new VerifierRegistry().register(makeVerifier())
    const audit = new InMemoryAuditLog()
    const receiver = new WebhookReceiver({
      verifiers,
      parsers: new Map<ProviderName, WebhookParser>(),
      tenantResolver: {
        resolve: async () => undefined,
      },
      store: new InMemoryWebhookEventStore(),
      audit,
      logger: pino({ level: 'silent' }),
    })

    const out = await receiver.receive({
      provider: 'maplerad',
      rawBody: BODY,
      headers: headers(),
    })

    expect(out.status).toBe('rejected')
    if (out.status === 'rejected') {
      expect(out.reason).toMatch(/no verifier\/parser|not mapped to a tenant|unresolved tenant/i)
    }

    expect((await audit.list(PLATFORM_TENANT))[0]?.action).toBe('webhook.rejected')
  })
})
