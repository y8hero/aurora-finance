import { describe, expect, it } from 'vitest'
import pino from 'pino'
import { MockAdapter, mockWebhookParser } from '../src/adapters/mock/MockAdapter'
import { InMemoryAuditLog } from '../src/core/audit/auditLog'
import { tenantId, type ProviderName } from '../src/core/types'
import { InMemoryWebhookEventStore } from '../src/webhooks/eventStore'
import { WebhookReceiver, type WebhookParser } from '../src/webhooks/receiver'
import { VerifierRegistry } from '../src/webhooks/signature'

const tbc = tenantId('tbc')
const FIXED_NOW = new Date('2026-05-01T12:00:00Z')
const nowSecs = Math.floor(FIXED_NOW.getTime() / 1000)

function setup() {
  const mock = new MockAdapter('test-webhook-secret-123', () => FIXED_NOW)
  const audit = new InMemoryAuditLog(() => FIXED_NOW)
  const store = new InMemoryWebhookEventStore()
  const receiver = new WebhookReceiver({
    verifiers: new VerifierRegistry().register(mock.verifier),
    parsers: new Map<ProviderName, WebhookParser>([['mock', mockWebhookParser]]),
    store,
    audit,
    logger: pino({ level: 'silent' }),
    now: () => FIXED_NOW,
  })
  return { mock, audit, store, receiver }
}

const body = JSON.stringify({ id: 'evt_001', type: 'collection.received', data: { amount: '100.00', currency: 'EUR' } })

describe('webhook receiver', () => {
  it('stores a correctly signed event exactly once and audits it', async () => {
    const { mock, receiver, store, audit } = setup()
    const headers = mock.signHeaders(body)

    const first = await receiver.receive({ provider: 'mock', tenantId: tbc, rawBody: body, headers })
    const second = await receiver.receive({ provider: 'mock', tenantId: tbc, rawBody: body, headers })

    expect(first.status).toBe('stored')
    expect(second.status).toBe('duplicate')
    expect(await store.list(tbc)).toHaveLength(1)

    const entries = await audit.list(tbc)
    expect(entries.map((e) => e.action)).toEqual(['webhook.stored', 'webhook.duplicate_ignored'])
    expect(await audit.verify(tbc)).toMatchObject({ ok: true })
  })

  it('rejects a bad signature and stores nothing', async () => {
    const { mock, receiver, store } = setup()
    const headers = { ...mock.signHeaders(body), 'x-mock-signature': 'deadbeef' }
    const out = await receiver.receive({ provider: 'mock', tenantId: tbc, rawBody: body, headers })
    expect(out.status).toBe('rejected')
    expect(await store.list(tbc)).toHaveLength(0)
  })

  it('rejects a tampered body', async () => {
    const { mock, receiver } = setup()
    const headers = mock.signHeaders(body)
    const tampered = body.replace('100.00', '999999.00')
    const out = await receiver.receive({ provider: 'mock', tenantId: tbc, rawBody: tampered, headers })
    expect(out.status).toBe('rejected')
  })

  it('rejects stale timestamps (replay protection)', async () => {
    const { mock, receiver } = setup()
    const headers = mock.signHeaders(body, nowSecs - 3600)
    const out = await receiver.receive({ provider: 'mock', tenantId: tbc, rawBody: body, headers })
    expect(out.status).toBe('rejected')
    if (out.status === 'rejected') expect(out.reason).toMatch(/tolerance|replay/)
  })

  it('rejects providers with no registered verifier (maplerad/circle in Phase 1)', async () => {
    const { receiver } = setup()
    const out = await receiver.receive({ provider: 'maplerad', tenantId: tbc, rawBody: body, headers: {} })
    expect(out.status).toBe('rejected')
  })

  it('rejects unparseable bodies after a valid signature', async () => {
    const { mock, receiver } = setup()
    const bad = JSON.stringify({ nope: true })
    const out = await receiver.receive({ provider: 'mock', tenantId: tbc, rawBody: bad, headers: mock.signHeaders(bad) })
    expect(out.status).toBe('rejected')
  })

  it('adapter.parseWebhook verifies and returns a ProviderEvent', async () => {
    const { mock } = setup()
    const evt = await mock.parseWebhook(body, mock.signHeaders(body))
    expect(evt).toMatchObject({ provider: 'mock', eventId: 'evt_001', eventType: 'collection.received' })
    await expect(mock.parseWebhook(body, {})).rejects.toThrow(/signature/)
  })
})
