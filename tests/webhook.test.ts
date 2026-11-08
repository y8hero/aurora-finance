import pino from 'pino'
import { describe, expect, it } from 'vitest'
import { MockAdapter, mockWebhookParser } from '../src/adapters/mock/MockAdapter'
import { InMemoryAuditLog } from '../src/core/audit/auditLog'
import { PLATFORM_TENANT, tenantId, type ProviderName } from '../src/core/types'
import { InMemoryWebhookEventStore } from '../src/webhooks/eventStore'
import { WebhookReceiver, type WebhookParser } from '../src/webhooks/receiver'
import { VerifierRegistry } from '../src/webhooks/signature'

const tbc = tenantId('tbc')
const other = tenantId('other')
const now = new Date('2026-05-01T12:00:00Z')

function setup() {
  const mock = new MockAdapter('test-webhook-secret-123', () => now)
  const audit = new InMemoryAuditLog(() => now)
  const store = new InMemoryWebhookEventStore()

  const receiver = new WebhookReceiver({
    verifiers: new VerifierRegistry().register(mock.verifier),
    parsers: new Map<ProviderName, WebhookParser>([['mock', mockWebhookParser]]),
    tenantResolver: mock.tenantResolver,
    store,
    audit,
    logger: pino({ level: 'silent' }),
    now: () => now,
  })

  return { mock, receiver, store, audit }
}

async function customer(mock: MockAdapter, tenant_id = tbc, name = 'User') {
  return mock.createCustomer({
    tenant_id,
    legalName: name,
    firstName: 'Test',
    lastName: name,
    email: `${name.toLowerCase()}@example.test`,
    country: 'GB',
    region: 'EU',
    beneficialOwners: [],
    sourceOfFundsRef: 'contract',
  })
}

describe('webhook receiver', () => {
  it('stores a verified event exactly once', async () => {
    const { mock, receiver, store } = setup()
    const c = await customer(mock)
    const body = JSON.stringify({
      id: 'evt_1',
      type: 'collection.received',
      provider_customer_id: c.externalId,
    })
    const headers = mock.signHeaders(body)

    const first = await receiver.receive({ provider: 'mock', rawBody: body, headers })
    const second = await receiver.receive({ provider: 'mock', rawBody: body, headers })

    expect(first.status).toBe('stored')
    expect(second.status).toBe('duplicate')
    expect(await store.list(tbc)).toHaveLength(1)
  })

  it('derives tenant from the verified payload mapping', async () => {
    const { mock, receiver } = setup()
    const c = await customer(mock, tbc)
    const body = JSON.stringify({
      id: 'evt_mapping',
      type: 'collection.received',
      provider_customer_id: c.externalId,
    })
    const result = await receiver.receive({
      provider: 'mock',
      rawBody: body,
      headers: mock.signHeaders(body),
    })

    expect(result.status).toBe('stored')
    if (result.status === 'stored') expect(result.record.tenant_id).toBe(tbc)
  })

  it('rejects a replay resolved to another tenant', async () => {
    const { mock, receiver, store, audit } = setup()
    const first = await customer(mock, tbc, 'Tbc')
    const second = await customer(mock, other, 'Other')
    const delivery = 'shared-delivery'
    const bodyA = JSON.stringify({
      id: 'event-a',
      type: 'test',
      provider_customer_id: first.externalId,
    })
    const bodyB = JSON.stringify({
      id: 'event-b',
      type: 'test',
      provider_customer_id: second.externalId,
    })

    const headersA = { ...mock.signHeaders(bodyA), 'svix-id': delivery }
    const headersB = { ...mock.signHeaders(bodyB), 'svix-id': delivery }

    expect((await receiver.receive({ provider: 'mock', rawBody: bodyA, headers: headersA })).status).toBe('stored')
    expect((await receiver.receive({ provider: 'mock', rawBody: bodyB, headers: headersB })).status).toBe('rejected')
    expect(await store.list(other)).toHaveLength(0)
    expect((await audit.list(PLATFORM_TENANT)).some((e) => e.action === 'webhook.rejected')).toBe(true)
  })

  it('rejects an unmapped customer and audits in the system scope', async () => {
    const { mock, receiver, audit, store } = setup()
    const body = JSON.stringify({
      id: 'unmapped',
      type: 'test',
      provider_customer_id: 'missing',
    })

    const result = await receiver.receive({
      provider: 'mock',
      rawBody: body,
      headers: mock.signHeaders(body),
    })

    expect(result.status).toBe('rejected')
    expect(await store.list(tbc)).toHaveLength(0)
    expect((await audit.list(PLATFORM_TENANT))[0]?.action).toBe('webhook.rejected')
  })

  it('rejects invalid signatures and stale timestamps', async () => {
    const { mock, receiver } = setup()
    const c = await customer(mock)
    const body = JSON.stringify({
      id: 'bad',
      type: 'test',
      provider_customer_id: c.externalId,
    })

    const bad = { ...mock.signHeaders(body), [ 'x-mock-signature' ]: 'invalid' }
    expect((await receiver.receive({ provider: 'mock', rawBody: body, headers: bad })).status).toBe('rejected')
    expect(
      (await receiver.receive({
        provider: 'mock',
        rawBody: body,
        headers: mock.signHeaders(body, Math.floor(now.getTime() / 1000) - 3601),
      })).status,
    ).toBe('rejected')
  })

  it('rejects unparseable and unregistered provider events', async () => {
    const { mock, receiver } = setup()
    const bad = '{}'
    expect((await receiver.receive({ provider: 'mock', rawBody: bad, headers: mock.signHeaders(bad) })).status).toBe('rejected')
    expect((await receiver.receive({ provider: 'maplerad', rawBody: bad, headers: {} })).status).toBe('rejected')
  })

  it('keeps tenant queries isolated', async () => {
    const { mock, receiver, store } = setup()
    const c = await customer(mock)
    const body = JSON.stringify({
      id: 'isolated',
      type: 'test',
      provider_customer_id: c.externalId,
    })
    await receiver.receive({ provider: 'mock', rawBody: body, headers: mock.signHeaders(body) })

    expect(await store.list(other)).toHaveLength(0)
    expect((await store.list(tbc))[0]?.tenant_id).toBe(tbc)
  })
})
