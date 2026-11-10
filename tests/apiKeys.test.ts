import { describe, expect, it } from 'vitest'
import {
  ApiKeyInvalidError,
  ApiKeyScopeError,
  ApiKeyService,
  ApiKeyTenantError,
  generateApiKey,
  hashApiKey,
} from '../src/core/apiKeys'
import {
  InMemoryApiKeyRepository,
  InMemoryCustomerRepository,
} from '../src/db/tenantRepositories'
import { PLATFORM_TENANT, tenantId } from '../src/core/types'
import { TokenBucketRateLimiter } from '../src/core/rateLimiter'

const tenant = tenantId('11111111-1111-4111-8111-111111111111')
const other = tenantId('22222222-2222-4222-8222-222222222222')

describe('API keys', () => {
  it('generates the required format and stores only a hash', async () => {
    const generated = generateApiKey()
    expect(generated.key).toMatch(/^aur_[a-f0-9]{8}_[A-Za-z0-9_-]{43}$/)
    expect(generated.prefix).toHaveLength(8)

    const repository = new InMemoryApiKeyRepository()
    const service = new ApiKeyService(repository)
    const created = await service.create(tenant, ['read'])
    const stored = await repository.findActiveByKeyHash(hashApiKey(created.key))

    expect(stored).toBeDefined()
    expect(stored?.tenant_id).toBe(tenant)
    expect(JSON.stringify(stored)).not.toContain(created.key)
    expect(stored).toHaveProperty('key_prefix', created.key_prefix)
    expect(stored).not.toHaveProperty('key_hash')
    expect(await repository.findActiveByKeyHash(created.key)).toBeUndefined()
  })

  it('authenticates scopes, rejects wrong keys and revoked keys', async () => {
    const repository = new InMemoryApiKeyRepository()
    const service = new ApiKeyService(repository)
    const created = await service.create(tenant, ['read'])

    await expect(service.authenticate(created.key, 'read')).resolves.toMatchObject({
      id: created.id,
    })
    await expect(service.authenticate(created.key, 'write')).rejects.toBeInstanceOf(
      ApiKeyScopeError,
    )
    await expect(
      service.authenticate(
        'aur_deadbeef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'read',
      ),
    ).rejects.toBeInstanceOf(ApiKeyInvalidError)

    await repository.revoke(tenant, created.id)
    await expect(service.authenticate(created.key, 'read')).rejects.toBeInstanceOf(
      ApiKeyInvalidError,
    )
  })

  it('refuses platform keys and cross-tenant operations', async () => {
    const repository = new InMemoryApiKeyRepository()
    const service = new ApiKeyService(repository)
    await expect(
      service.create(PLATFORM_TENANT, ['read']),
    ).rejects.toBeInstanceOf(ApiKeyTenantError)

    const customers = new InMemoryCustomerRepository()
    const customer = await customers.create(tenant, {
      first_name: 'A',
      last_name: 'B',
      email: 'a@example.test',
      country: 'GB',
    })
    expect(await customers.get(other, customer.id)).toBeUndefined()
    expect(await customers.list(other, 10)).toHaveLength(0)
    await expect(customers.getByExternalRef(other, 'missing')).resolves.toBeUndefined()
  })

  it('enforces customer external_ref per tenant', async () => {
    const customers = new InMemoryCustomerRepository()
    await customers.create(tenant, {
      external_ref: 'ref-1',
      first_name: 'A',
      last_name: 'B',
      email: 'a@example.test',
      country: 'GB',
    })
    await expect(
      customers.create(tenant, {
        external_ref: 'ref-1',
        first_name: 'C',
        last_name: 'D',
        email: 'c@example.test',
        country: 'GB',
      }),
    ).rejects.toThrow(/external_ref/)
    await expect(
      customers.create(other, {
        external_ref: 'ref-1',
        first_name: 'C',
        last_name: 'D',
        email: 'c@example.test',
        country: 'GB',
      }),
    ).resolves.toBeDefined()
  })

  it('rate limits and refills', () => {
    let now = 0
    const limiter = new TokenBucketRateLimiter(2, 1, () => now)
    expect(limiter.consume('tenant').allowed).toBe(true)
    expect(limiter.consume('tenant').allowed).toBe(true)
    expect(limiter.consume('tenant').allowed).toBe(false)
    now = 1000
    expect(limiter.consume('tenant').allowed).toBe(true)
  })
})
