import { describe, expect, it } from 'vitest'
import { CircleAdapter } from '../src/adapters/circle/CircleAdapter'
import {
  assertMapleradObservedCurrency,
  MapleradAdapter,
  MapleradUnsupportedCurrencyError,
} from '../src/adapters/maplerad/MapleradAdapter'
import { Secret } from '../src/config/env'
import type { HttpTransport } from '../src/providers/http'

function transport(
  status: number,
  body: unknown,
  seen: { url?: string; headers?: Record<string, string> },
): HttpTransport {
  return {
    async get(request) {
      seen.url = request.url
      seen.headers = { ...request.headers }
      return { status, body }
    },
  }
}

describe('read-only provider probes', () => {
  it('Maplerad checkAuth uses only GET /v1/countries and Bearer auth', async () => {
    const seen: { url?: string; headers?: Record<string, string> } = {}
    const adapter = new MapleradAdapter({
      environment: 'sandbox',
      secretKey: new Secret('not-used-in-output'),
      transport: transport(200, { countries: [] }, seen),
    })

    await adapter.checkAuth()

    expect(seen.url).toBe('https://api.maplerad.com/v1/countries')
    expect(seen.headers?.Authorization).toBe('Bearer not-used-in-output')
  })

  it('Circle checkAuth uses only GET publicKey', async () => {
    const seen: { url?: string; headers?: Record<string, string> } = {}
    const adapter = new CircleAdapter({
      environment: 'testnet',
      apiKey: new Secret('PREFIX:ID:SECRET'),
      transport: transport(200, { data: { publicKey: 'redact-me' } }, seen),
    })

    await adapter.checkAuth()

    expect(seen.url).toBe('https://api.circle.com/v1/w3s/config/entity/publicKey')
    expect(seen.headers?.Authorization).toBe('Bearer PREFIX:ID:SECRET')
  })

  it('rejects redirects without following them', async () => {
    const adapter = new CircleAdapter({
      environment: 'testnet',
      apiKey: new Secret('PREFIX:ID:SECRET'),
      transport: transport(302, {}, {}),
    })

    await expect(adapter.checkAuth()).rejects.toThrow(/redirect/)
  })

  it('produces only structural Circle response shapes', async () => {
    const adapter = new CircleAdapter({
      environment: 'testnet',
      apiKey: new Secret('PREFIX:ID:SECRET'),
      transport: transport(
        200,
        {
          data: {
            wallets: [
              {
                id: 'secret-id',
                address: 'secret-address',
                balance: '100',
              },
            ],
          },
        },
        {},
      ),
    })

    const result = await adapter.probeWallets()

    expect(result.shape).toEqual({
      type: 'object',
      fields: {
        data: {
          type: 'object',
          fields: {
            wallets: {
              type: 'array',
              items: {
                type: 'object',
                fields: {
                  id: { type: 'string' },
                  address: { type: 'string' },
                  balance: { type: 'string' },
                },
              },
            },
          },
        },
      },
    })
  })

  it('accepts each observed sandbox currency code', () => {
    for (const currency of [
      'NGN',
      'USD',
      'GHS',
      'KES',
      'TZS',
      'UGX',
      'MWK',
      'MZN',
      'PYUSD',
      'RWF',
      'CDF',
      'ZAR',
      'SLE',
      'LRD',
      'XAF',
      'XOF',
      'USDT',
      'USDC',
    ]) {
      expect(() => assertMapleradObservedCurrency(currency)).not.toThrow()
    }
  })

  it('rejects an unobserved currency before any provider call', async () => {
    let calls = 0
    const adapter = new MapleradAdapter({
      environment: 'sandbox',
      secretKey: new Secret('not-used-in-output'),
      transport: {
        async get() {
          calls += 1
          return { status: 200, body: {} }
        },
      },
    })

    await expect(
      adapter.createAccount({
        tenant_id: 'tenant_test' as never,
        customerExternalId: 'customer_test',
        currency: 'EUR',
        type: 'wallet',
      }),
    ).rejects.toBeInstanceOf(MapleradUnsupportedCurrencyError)

    expect(calls).toBe(0)
  })
})
