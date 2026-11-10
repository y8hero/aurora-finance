import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import { buildApp, OPENAPI_ROUTE_PATHS, type AppDeps } from '../src/app'
import { InMemoryAuditLog } from '../src/core/audit/auditLog'
import { InMemoryTenantRepository } from '../src/core/tenants'
import {
  InMemoryApiKeyRepository,
  InMemoryCustomerRepository,
} from '../src/db/tenantRepositories'
import { ApiKeyService } from '../src/core/apiKeys'
import { IdempotencyStore } from '../src/core/idempotency'
import { TokenBucketRateLimiter } from '../src/core/rateLimiter'
import { MockAdapter, mockWebhookParser } from '../src/adapters/mock/MockAdapter'
import { InMemoryWebhookEventStore } from '../src/webhooks/eventStore'
import { VerifierRegistry } from '../src/webhooks/signature'
import { WebhookReceiver } from '../src/webhooks/receiver'
import { createLogger } from '../src/logging/logger'
import type { AppConfig } from '../src/config/env'

function setup() {
  const config: AppConfig = {
    AURORA_ENV: 'development',
    PORT: 3000,
    LOG_LEVEL: 'silent',
    DATABASE_URL: undefined,
    DATABASE_CA_CERT_PATH: undefined,
    AURORA_ADMIN_API_KEY: undefined,
    MAPLERAD_ENV: 'sandbox',
    MAPLERAD_BASE_URL: 'https://api.maplerad.com',
    MAPLERAD_SECRET_KEY_SANDBOX: undefined,
    MAPLERAD_WEBHOOK_SECRET: undefined,
    MAPLERAD_WEBHOOK_ALLOWED_IPS: [],
    CIRCLE_ENV: 'testnet',
    CIRCLE_API_KEY_TESTNET: undefined,
    CIRCLE_API_KEY_MAINNET: undefined,
    CIRCLE_BASE_URL_TESTNET: undefined,
    CIRCLE_BASE_URL_MAINNET: undefined,
    MOCK_WEBHOOK_SECRET: 'dev-only-mock-secret-change-me',
  }

  const audit = new InMemoryAuditLog()
  const tenants = new InMemoryTenantRepository()
  const apiKeys = new InMemoryApiKeyRepository()
  const customers = new InMemoryCustomerRepository()
  const mock = new MockAdapter(config.MOCK_WEBHOOK_SECRET)
  const receiver = new WebhookReceiver({
    verifiers: new VerifierRegistry().register(mock.verifier),
    parsers: new Map([['mock', mockWebhookParser]]),
    tenantResolver: mock.tenantResolver,
    store: new InMemoryWebhookEventStore(),
    audit,
    logger: createLogger('silent'),
  })
  const deps: AppDeps = {
    config,
    logger: createLogger('silent'),
    audit,
    tenants,
    apiKeys,
    customers,
    apiKeyService: new ApiKeyService(apiKeys),
    receiver,
    idempotency: new IdempotencyStore(),
    tenantLimiter: new TokenBucketRateLimiter(100, 1),
    ipLimiter: new TokenBucketRateLimiter(100, 1),
  }

  return { app: buildApp(deps), apiKeys, tenants, customers }
}

describe('Stage B HTTP API', () => {
  it('has the same route paths as OpenAPI', async () => {
    const { app } = setup()
    const spec = parse(await readFile('docs/openapi.yaml', 'utf8'))
    const actual = new Set(
      OPENAPI_ROUTE_PATHS.map((path) => path.replace(/:([^/]+)/g, '{$1}')),
    )
    const documented = new Set(Object.keys(spec.paths))
    expect(actual).toEqual(documented)
    await app.close()
  })

  it('requires authentication for tenant and admin routes', async () => {
    const { app } = setup()

    for (const url of [
      '/v1/admin/tenants',
      '/v1/customers',
      '/v1/audit',
      '/v1/audit/verify',
    ]) {
      const response = await app.inject({ method: 'GET', url })
      expect(response.statusCode).toBe(
        url.startsWith('/v1/admin') ? 404 : 401,
      )
      expect(response.json().error.requestId).toBeTruthy()
    }

    await app.close()
  })

  it('returns 404 for admin routes when no admin key is configured', async () => {
    const { app } = setup()
    const response = await app.inject({
      method: 'GET',
      url: '/v1/admin/tenants',
    })

    expect(response.statusCode).toBe(404)
    expect(response.json()).toMatchObject({
      error: {
        code: 'not_found',
        message: 'not found',
      },
    })

    await app.close()
  })

  it('isolates customer reads and supports idempotent creation', async () => {
    const { app, apiKeys, tenants } = setup()
    const firstTenant = await tenants.create({
      slug: 'a',
      name: 'A',
      country: 'NG',
    })
    const secondTenant = await tenants.create({
      slug: 'b',
      name: 'B',
      country: 'GB',
    })
    const first = await new ApiKeyService(apiKeys).create(firstTenant.id, [
      'read',
      'write',
    ])
    const second = await new ApiKeyService(apiKeys).create(secondTenant.id, [
      'read',
      'write',
    ])
    const payload = {
      first_name: 'A',
      last_name: 'User',
      email: 'a@example.test',
      country: 'NG',
    }
    const headers = {
      authorization: `Bearer ${first.key}`,
      'idempotency-key': 'customer-1',
    }

    const created = await app.inject({
      method: 'POST',
      url: '/v1/customers',
      headers,
      payload,
    })
    const replay = await app.inject({
      method: 'POST',
      url: '/v1/customers',
      headers,
      payload,
    })

    expect(created.statusCode).toBe(422)
    expect(replay.statusCode).toBe(422)

    const crossRead = await app.inject({
      method: 'GET',
      url: '/v1/customers/00000000-0000-0000-0000-000000000000',
      headers: { authorization: `Bearer ${second.key}` },
    })
    expect(crossRead.statusCode).toBe(404)

    await app.close()
  })

  it('keeps provider routes disabled and jurisdiction screening fail-closed', async () => {
    const { app, apiKeys, tenants, customers } = setup()
    const tenant = await tenants.create({
      slug: 'c',
      name: 'C',
      country: 'NG',
    })
    const key = await new ApiKeyService(apiKeys).create(tenant.id, [
      'read',
      'write',
    ])

    const rejected = await app.inject({
      method: 'POST',
      url: '/v1/customers',
      headers: {
        authorization: `Bearer ${key.key}`,
        'idempotency-key': 'jurisdiction-test-1',
      },
      payload: {
        first_name: 'A',
        last_name: 'B',
        email: 'a@example.test',
        country: 'NG',
      },
    })

    expect(rejected.statusCode).toBe(422)
    expect(rejected.json().error.code).toBe('jurisdiction_review_required')
    expect(await customers.list(tenant.id, 100)).toHaveLength(0)

    const unavailable = await app.inject({
      method: 'GET',
      url: '/v1/accounts',
      headers: { authorization: `Bearer ${key.key}` },
    })
    expect(unavailable.statusCode).toBe(501)
    expect(unavailable.json().error.code).toBe('provider_unverified')
    await app.close()
  })
})
