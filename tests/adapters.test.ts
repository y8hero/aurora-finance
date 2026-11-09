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
  country: 'GB',
  region: 'EU',
  beneficialOwners: [{ name: 'Walter Example', role: 'director' }],
  sourceOfFundsRef: 'gov-contract-1',
}

const webhookSecret = `whsec_${Buffer.from(
  'adapter-test-webhook-key-000000000',
).toString('base64')}`

describe('Maplerad adapter', () => {
  const adapter = new MapleradAdapter({
    environment: 'sandbox',
    secretKey: new Secret('sk_test_x'),
    webhookSecret: new Secret(webhookSecret),
    transport: {
      async get() {
        return { status: 200, body: {} }
      },
    },
  })

  it('uses the single verified base URL and refuses non-https', () => {
    expect(MAPLERAD_BASE_URL).toBe('https://api.maplerad.com')
    expect(adapter.baseUrl).toBe('https://api.maplerad.com')
    expect(
      new MapleradAdapter({
        environment: 'sandbox',
        baseUrl: 'https://api.maplerad.com/',
      }).baseUrl,
    ).toBe('https://api.maplerad.com')
    expect(
      () =>
        new MapleradAdapter({
          environment: 'sandbox',
          baseUrl: 'http://api.maplerad.com',
        }),
    ).toThrow(MapleradInputError)
  })

  it('builds the verified Bearer header', () => {
    expect(mapleradAuthorizationHeader(new Secret('sk_test_x'))).toBe(
      'Bearer sk_test_x',
    )
  })

  it('does not retain or serialise the secret', () => {
    expect(JSON.stringify(adapter)).not.toContain('sk_test_x')
    expect(adapter.hasSecretKey).toBe(true)
  })

  it('maps CustomerInput to the verified create-customer body', () => {
    expect(toMapleradCreateCustomerBody(customerInput)).toEqual({
      first_name: 'Walter',
      last_name: 'Example',
      email: 'walter@example.test',
      country: 'GB',
    })

    expect(() =>
      toMapleradCreateCustomerBody({ ...customerInput, email: ' ' }),
    ).toThrow(MapleradInputError)
    expect(() =>
      toMapleradCreateCustomerBody({ ...customerInput, firstName: '' }),
    ).toThrow(/first_name/)
  })

  it('prepares but never sends the create-customer request', () => {
    const request = adapter.prepareCreateCustomer(customerInput)

    expect(request.method).toBe('POST')
    expect(request.url).toBe(
      `https://api.maplerad.com${MAPLERAD_PATHS.createCustomer}`,
    )
    expect(request.headers.Authorization).toBe('Bearer sk_test_x')
    expect(request.headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(request.body ?? '')).toEqual({
      first_name: 'Walter',
      last_name: 'Example',
      email: 'walter@example.test',
      country: 'GB',
    })

    const noKey = new MapleradAdapter({ environment: 'sandbox' })
    expect(() => noKey.prepareCreateCustomer(customerInput)).toThrow(
      /MAPLERAD_SECRET_KEY_SANDBOX/,
    )
  })

  it('checkAuth performs the verified read-only countries probe', async () => {
    let calls = 0
    const checked = new MapleradAdapter({
      environment: 'sandbox',
      secretKey: new Secret('sk_test_x'),
      transport: {
        async get(request) {
          calls += 1
          expect(request.url).toBe('https://api.maplerad.com/v1/countries')
          expect(request.headers.Authorization).toBe('Bearer sk_test_x')
          return { status: 200, body: { countries: [] } }
        },
      },
    })

    await expect(checked.checkAuth()).resolves.toBeUndefined()
    expect(calls).toBe(1)
  })

  it('throws UNVERIFIED from every still-unverified Maplerad method', async () => {
    const calls: Array<() => Promise<unknown>> = [
      () => adapter.createCustomer(customerInput),
      () =>
        adapter.upgradeCustomerKyc({
          tenant_id: tbc,
          customerExternalId: 'c',
          targetTier: 1,
        }),
      () =>
        adapter.createAccount({
          tenant_id: tbc,
          customerExternalId: 'c',
          currency: 'USD',
          type: 'treasury',
        }),
      () => adapter.getBalances(tbc),
      () =>
        adapter.quoteFx({
          tenant_id: tbc,
          sell: { amount: '1', currency: 'USD' },
          buyCurrency: 'NGN',
        }),
      () => adapter.executeFx(tbc, 'q'),
      () =>
        adapter.createPayout(
          {
            tenant_id: tbc,
            counterpartyId: 'cp',
            amount: { amount: '1', currency: 'USD' },
            reference: 'Support',
            purposeCategory: 'charity',
          },
          'k',
        ),
      () =>
        adapter.issueCard({
          tenant_id: tbc,
          customerExternalId: 'c',
          currency: 'USD',
          kind: 'virtual',
        }),
    ]

    for (const call of calls) {
      await expect(call()).rejects.toBeInstanceOf(UnverifiedError)
      await expect(call()).rejects.toThrow(/^UNVERIFIED: complete Phase 0/)
    }
  })

  it('rejects a bad webhook signature before checking the unverified event schema', async () => {
    const body = '{"event":"unverified.test"}'

    await expect(
      adapter.parseWebhook(body, {
        'svix-id': 'msg_bad_signature',
        'svix-timestamp': String(Math.floor(Date.now() / 1000)),
        'svix-signature': 'v1,invalid',
      }),
    ).rejects.toThrow(/Maplerad webhook signature invalid/)
  })

  it('rejects a correctly signed webhook as UNVERIFIED when its event schema is unknown', async () => {
    const body = '{"event":"unverified.test"}'
    const svixId = 'msg_valid_signature'
    const svixTimestamp = String(Math.floor(Date.now() / 1000))
    const verifier = adapter.webhookVerifier

    expect(verifier).toBeDefined()

    const signature = verifier!.sign(body, svixId, svixTimestamp)

    await expect(
      adapter.parseWebhook(body, {
        'svix-id': svixId,
        'svix-timestamp': svixTimestamp,
        'svix-signature': signature,
      }),
    ).rejects.toBeInstanceOf(UnverifiedError)

    await expect(
      adapter.parseWebhook(body, {
        'svix-id': svixId,
        'svix-timestamp': svixTimestamp,
        'svix-signature': signature,
      }),
    ).rejects.toThrow(/^UNVERIFIED: complete Phase 0/)
  })

  it('uses the new missing webhook secret message', async () => {
    const noSecret = new MapleradAdapter({ environment: 'sandbox' })

    await expect(noSecret.parseWebhook('{}', {})).rejects.toThrow(
      /MAPLERAD_WEBHOOK_SECRET/,
    )
  })

  it('documents the verified API areas', () => {
    expect(MAPLERAD_API_AREAS).toContain('FX')
    expect(MAPLERAD_API_AREAS).toContain('Issuing')
    expect(MAPLERAD_API_AREAS).toHaveLength(12)
  })
})

describe('Circle adapter', () => {
  it('checkAuth performs the verified read-only public-key probe', async () => {
    const adapter = new CircleAdapter({
      environment: 'testnet',
      apiKey: new Secret('PREFIX:ID:SECRET'),
      transport: {
        async get(request) {
          expect(request.url).toBe(
            'https://api.circle.com/v1/w3s/config/entity/publicKey',
          )
          expect(request.headers.Authorization).toBe(
            'Bearer PREFIX:ID:SECRET',
          )
          return { status: 200, body: { data: { publicKey: 'redacted' } } }
        },
      },
    })

    await expect(adapter.checkAuth()).resolves.toBeUndefined()
  })

  it('throws UNVERIFIED from every still-unverified Circle method', async () => {
    const adapter = new CircleAdapter({
      environment: 'testnet',
      apiKey: new Secret('PREFIX:ID:SECRET'),
      transport: {
        async get() {
          return { status: 200, body: {} }
        },
      },
    })

    const calls: Array<() => Promise<unknown>> = [
      () =>
        adapter.createAccount({
          tenant_id: tbc,
          customerExternalId: 'c',
          currency: 'USDC',
          type: 'wallet',
          chain: 'SOL',
        }),
      () => adapter.getBalances(tbc),
      () => adapter.parseWebhook('{}', {}),
    ]

    for (const call of calls) {
      await expect(call()).rejects.toBeInstanceOf(UnverifiedError)
      await expect(call()).rejects.toThrow(/^UNVERIFIED: complete Phase 0/)
    }

    expect(() => adapter.resolveAssetAddress('USDC', 'SOL')).toThrow(
      UnverifiedError,
    )
  })

  it('reports the missing Circle key by variable name only', async () => {
    const adapter = new CircleAdapter({ environment: 'testnet' })

    await expect(adapter.checkAuth()).rejects.toThrow(
      /CIRCLE_API_KEY_TESTNET/,
    )
  })
})

describe('Mock adapter', () => {
  it('implements the ProviderAdapter happy path', async () => {
    const mock: ProviderAdapter = new MockAdapter('secret-for-tests-1234')
    await mock.checkAuth()

    const customer = await mock.createCustomer!(customerInput)
    expect(customer.tenant_id).toBe(tbc)

    const account = await mock.createAccount!({
      tenant_id: tbc,
      customerExternalId: customer.externalId,
      currency: 'EUR',
      type: 'treasury',
    })

    const balances = await mock.getBalances(tbc)
    expect(balances).toEqual([
      {
        tenant_id: tbc,
        accountExternalId: account.externalId,
        available: { amount: '0', currency: 'EUR' },
      },
    ])
  })

  it('createPayout is idempotent per tenant and key', async () => {
    const mock = new MockAdapter('secret-for-tests-1234')
    const input = {
      tenant_id: tbc,
      counterpartyId: 'cp1',
      amount: { amount: '5000', currency: 'USD' },
      reference: 'Programme support',
      purposeCategory: 'food-security',
    }

    const first = await mock.createPayout(input, 'idem-1')
    const second = await mock.createPayout(input, 'idem-1')

    expect(second.providerRef).toBe(first.providerRef)
    expect(
      mock.calls.filter((call) => call.method === 'createPayout'),
    ).toHaveLength(1)

    await expect(
      mock.createPayout(
        { ...input, amount: { amount: '6000', currency: 'USD' } },
        'idem-1',
      ),
    ).rejects.toBeInstanceOf(IdempotencyConflictError)
  })
})
