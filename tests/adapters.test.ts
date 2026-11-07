import { describe, expect, it } from 'vitest'
import { CircleAdapter } from '../src/adapters/circle/CircleAdapter'
import {
  MAPLERAD_API_AREAS,
  MAPLERAD_BASE_URL,
  MAPLERAD_PATHS,
  MapleradAdapter,
  MapleradInputError,
  mapleradAuthorizationHeader,
  toMapleradCreateCustomerBody,
} from '../src/adapters/maplerad/MapleradAdapter'
import { MockAdapter } from '../src/adapters/mock/MockAdapter'
import type { CustomerInput, ProviderAdapter } from '../src/adapters/types'
import { UnverifiedError } from '../src/adapters/unverified'
import { Secret } from '../src/config/env'
import { IdempotencyConflictError } from '../src/core/idempotency'
import { tenantId } from '../src/core/types'

const tbc = tenantId('tbc')

const customerInput: CustomerInput = {
  tenant_id: tbc,
  legalName: 'The Binding Circle Ltd',
  firstName: 'Walter',
  lastName: 'Example',
  email: 'walter@example.test',
  country: 'gb',
  region: 'EU',
  beneficialOwners: [{ name: 'Walter Example', role: 'director' }],
  sourceOfFundsRef: 'gov-contract-1',
}

const WEBHOOK_SECRET = `whsec_${Buffer.from('adapter-test-webhook-key-000000000').toString('base64')}`

describe('Maplerad adapter — verified facts encoded, no live calls', () => {
  const adapter = new MapleradAdapter({
    environment: 'sandbox',
    secretKey: new Secret('sk_test_x'),
    webhookSecret: new Secret(WEBHOOK_SECRET),
  })

  it('uses the single verified base URL and refuses non-https', () => {
    expect(MAPLERAD_BASE_URL).toBe('https://api.maplerad.com')
    expect(adapter.baseUrl).toBe('https://api.maplerad.com')
    expect(new MapleradAdapter({ environment: 'sandbox', baseUrl: 'https://api.maplerad.com/' }).baseUrl).toBe('https://api.maplerad.com')
    expect(() => new MapleradAdapter({ environment: 'sandbox', baseUrl: 'http://api.maplerad.com' })).toThrow(MapleradInputError)
  })

  it('builds the verified Bearer header only at the point of use', () => {
    expect(mapleradAuthorizationHeader(new Secret('sk_test_x'))).toBe('Bearer sk_test_x')
  })

  it('does not retain or serialise the secret', () => {
    expect(JSON.stringify(adapter)).not.toContain('sk_test_x')
    expect(adapter.hasSecretKey).toBe(true)
  })

  it('maps CustomerInput to the verified POST /v1/customers body (exactly four fields)', () => {
    const body = toMapleradCreateCustomerBody(customerInput)
    expect(body).toEqual({ first_name: 'Walter', last_name: 'Example', email: 'walter@example.test', country: 'GB' })
    expect(Object.keys(body).sort()).toEqual(['country', 'email', 'first_name', 'last_name'])
    expect(() => toMapleradCreateCustomerBody({ ...customerInput, email: ' ' })).toThrow(MapleradInputError)
    expect(() => toMapleradCreateCustomerBody({ ...customerInput, firstName: '' })).toThrow(/first_name/)
  })

  it('prepares (but never sends) the create-customer request', () => {
    const req = adapter.prepareCreateCustomer(customerInput)
    expect(req.method).toBe('POST')
    expect(req.url).toBe(`https://api.maplerad.com${MAPLERAD_PATHS.createCustomer}`)
    expect(req.url).toBe('https://api.maplerad.com/v1/customers')
    expect(req.headers.Authorization).toBe('Bearer sk_test_x')
    expect(req.headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(req.body ?? '')).toEqual({ first_name: 'Walter', last_name: 'Example', email: 'walter@example.test', country: 'GB' })

    const noKey = new MapleradAdapter({ environment: 'sandbox' })
    expect(() => noKey.prepareCreateCustomer(customerInput)).toThrow(/secret key not configured/)
  })

  it('throws UNVERIFIED from every ProviderAdapter method (response/payload shapes unconfirmed)', async () => {
    const calls: Promise<unknown>[] = [
      adapter.checkAuth(),
      adapter.createCustomer(customerInput),
      adapter.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: 'c', targetTier: 1 }),
      adapter.createAccount({ tenant_id: tbc, customerExternalId: 'c', currency: 'USD', type: 'treasury' }),
      adapter.getBalances(tbc),
      adapter.quoteFx({ tenant_id: tbc, sell: { amount: '1', currency: 'USD' }, buyCurrency: 'NGN' }),
      adapter.executeFx(tbc, 'q'),
      adapter.createPayout({ tenant_id: tbc, counterpartyId: 'cp', amount: { amount: '1', currency: 'USD' }, reference: 'Support', purposeCategory: 'charity' }, 'k'),
      adapter.issueCard({ tenant_id: tbc, customerExternalId: 'c', currency: 'USD', kind: 'virtual' }),
    ]
    for (const c of calls) {
      await expect(c).rejects.toBeInstanceOf(UnverifiedError)
      await expect(c).rejects.toThrow(/^UNVERIFIED: complete Phase 0/)
    }
  })

  it('createCustomer validates the verified body shape before refusing', async () => {
    await expect(adapter.createCustomer({ ...customerInput, email: '' })).rejects.toBeInstanceOf(MapleradInputError)
  })

  it('parseWebhook enforces the verified signature, then refuses on the unverified payload', async () => {
    const verifier = adapter.webhookVerifier!
    const body = '{"anything":true}'
    const id = 'msg_adapter_test'
    const ts = String(Math.floor(Date.now() / 1000))

    await expect(adapter.parseWebhook(body, {})).rejects.toThrow(/signature invalid/)
    await expect(
      adapter.parseWebhook(body, { 'svix-id': id, 'svix-timestamp': ts, 'svix-signature': 'v1,AAAA' }),
    ).rejects.toThrow(/signature invalid/)

    const good = { 'svix-id': id, 'svix-timestamp': ts, 'svix-signature': verifier.sign(body, id, ts) }
    await expect(adapter.parseWebhook(body, good)).rejects.toBeInstanceOf(UnverifiedError)
    await expect(adapter.parseWebhook(body, good)).rejects.toThrow(/event names and payload/)

    const noSecret = new MapleradAdapter({ environment: 'sandbox' })
    expect(noSecret.webhookVerifier).toBeUndefined()
    await expect(noSecret.parseWebhook(body, good)).rejects.toThrow(/signing secret not configured/)
  })

  it('documents the verified API areas', () => {
    expect(MAPLERAD_API_AREAS).toContain('FX')
    expect(MAPLERAD_API_AREAS).toContain('Issuing')
    expect(MAPLERAD_API_AREAS).toHaveLength(12)
  })
})

describe('Circle stub', () => {
  const adapter = new CircleAdapter({ environment: 'testnet', apiKey: new Secret('TEST_API_KEY:a:b') })

  it('does not retain the key', () => {
    expect(JSON.stringify(adapter)).not.toContain('TEST_API_KEY')
    expect(adapter.hasApiKey).toBe(true)
    expect(adapter.hasBaseUrl).toBe(false)
  })

  it('throws UNVERIFIED from every method, including address resolution', async () => {
    await expect(adapter.checkAuth()).rejects.toBeInstanceOf(UnverifiedError)
    await expect(adapter.getBalances(tbc)).rejects.toBeInstanceOf(UnverifiedError)
    await expect(adapter.createAccount({ tenant_id: tbc, customerExternalId: 'c', currency: 'USDC', type: 'wallet', chain: 'SOL' })).rejects.toBeInstanceOf(UnverifiedError)
    await expect(adapter.parseWebhook('{}', {})).rejects.toBeInstanceOf(UnverifiedError)
    expect(() => adapter.resolveAssetAddress('USDC', 'SOL')).toThrow(UnverifiedError)
  })
})

describe('Mock adapter (interface conformance)', () => {
  it('implements the ProviderAdapter happy path', async () => {
    const mock: ProviderAdapter = new MockAdapter('secret-for-tests-1234')
    await mock.checkAuth()
    const cus = await mock.createCustomer!(customerInput)
    expect(cus.tenant_id).toBe(tbc)
    expect(cus.kycTier).toBe(0)

    const upgraded = await mock.upgradeCustomerKyc!({
      tenant_id: tbc,
      customerExternalId: cus.externalId,
      targetTier: 1,
      tier1: { phone: '+440000000000', dateOfBirth: '1980-01-01', identificationNumber: 'ID-000', homeAddress: '1 Example St' },
    })
    expect(upgraded.kycTier).toBe(1)

    const acc = await mock.createAccount!({ tenant_id: tbc, customerExternalId: cus.externalId, currency: 'EUR', type: 'virtual_account' })
    const balances = await mock.getBalances(tbc)
    expect(balances).toEqual([{ tenant_id: tbc, accountExternalId: acc.externalId, available: { amount: '0.00', currency: 'EUR' } }])
    expect(await mock.getBalances(tenantId('someone-else'))).toEqual([])

    const quote = await mock.quoteFx!({ tenant_id: tbc, sell: { amount: '100', currency: 'EUR' }, buyCurrency: 'USD' })
    const fx = await mock.executeFx!(tbc, quote.quoteRef)
    expect(fx.quoteRef).toBe(quote.quoteRef)
    await expect(mock.executeFx!(tenantId('someone-else'), quote.quoteRef)).rejects.toThrow()
  })

  it('createPayout is idempotent per (tenant, key) and rejects payload drift', async () => {
    const mock = new MockAdapter('secret-for-tests-1234')
    const input = { tenant_id: tbc, counterpartyId: 'cp1', amount: { amount: '50.00', currency: 'USD' }, reference: 'Programme support', purposeCategory: 'food-security' }
    const a = await mock.createPayout(input, 'idem-1')
    const b = await mock.createPayout(input, 'idem-1')
    expect(b.providerRef).toBe(a.providerRef)
    expect(mock.calls.filter((c) => c.method === 'createPayout')).toHaveLength(1)
    await expect(mock.createPayout({ ...input, amount: { amount: '60.00', currency: 'USD' } }, 'idem-1')).rejects.toBeInstanceOf(IdempotencyConflictError)
    const other = await mock.createPayout({ ...input, tenant_id: tenantId('someone-else') }, 'idem-1')
    expect(other.providerRef).not.toBe(a.providerRef)
  })
})
