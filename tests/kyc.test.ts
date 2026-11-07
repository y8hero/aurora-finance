import { describe, expect, it } from 'vitest'
import { MockAdapter } from '../src/adapters/mock/MockAdapter'
import type { CustomerInput } from '../src/adapters/types'
import {
  KYC_TIER_DATA_REQUIRED,
  KycTierError,
  REQUIRED_KYC_TIER,
  assertKycTierAllows,
  canUseFeature,
  featureForAccountType,
  isKycTier,
} from '../src/core/kyc/kycTier'
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

const tier1 = { phone: '+440000000000', dateOfBirth: '1980-01-01', identificationNumber: 'ID-000', homeAddress: '1 Example St' }
const tier2 = { identityDocument: { type: 'NIN', number: 'NIN-000' } }

describe('KYC tier model (verified from maplerad.dev/docs/customers)', () => {
  it('maps features to the verified minimum tiers', () => {
    expect(REQUIRED_KYC_TIER).toEqual({ bills: 0, fx: 0, transfers: 0, collections: 1, issuing: 1 })
    expect(KYC_TIER_DATA_REQUIRED[0]).toEqual(['first_name', 'last_name', 'email'])
    expect(KYC_TIER_DATA_REQUIRED[1]).toHaveLength(4)
    expect(KYC_TIER_DATA_REQUIRED[2]).toHaveLength(1)
  })

  it('canUseFeature / assertKycTierAllows', () => {
    expect(canUseFeature(0, 'fx')).toBe(true)
    expect(canUseFeature(0, 'collections')).toBe(false)
    expect(canUseFeature(1, 'collections')).toBe(true)
    expect(canUseFeature(1, 'issuing')).toBe(true)
    expect(() => assertKycTierAllows({ tenant_id: tbc, customerExternalId: 'c1', kycTier: 0, feature: 'issuing' })).toThrow(KycTierError)
    try {
      assertKycTierAllows({ tenant_id: tbc, customerExternalId: 'c1', kycTier: 0, feature: 'collections' })
    } catch (e) {
      const err = e as KycTierError
      expect(err.requiredTier).toBe(1)
      expect(err.actualTier).toBe(0)
      expect(err.feature).toBe('collections')
      expect(err.message).toMatch(/tier 0.*requires tier 1/)
    }
  })

  it('gates virtual accounts (collections) and cards (issuing); wallets are not gated (tier UNVERIFIED)', () => {
    expect(featureForAccountType('virtual_account')).toBe('collections')
    expect(featureForAccountType('card')).toBe('issuing')
    expect(featureForAccountType('wallet')).toBeUndefined()
    expect(featureForAccountType('treasury')).toBeUndefined()
    expect(featureForAccountType('spend')).toBeUndefined()
  })

  it('isKycTier', () => {
    expect(isKycTier(0)).toBe(true)
    expect(isKycTier(2)).toBe(true)
    expect(isKycTier(3)).toBe(false)
    expect(isKycTier('1')).toBe(false)
  })
})

describe('Mock adapter enforces KYC tiers per customer', () => {
  it('new customers start at Tier 0 and cannot get collections or cards', async () => {
    const mock = new MockAdapter('secret-for-tests-1234')
    const cus = await mock.createCustomer(customerInput)
    expect(cus.kycTier).toBe(0)

    await expect(
      mock.createAccount({ tenant_id: tbc, customerExternalId: cus.externalId, currency: 'NGN', type: 'virtual_account' }),
    ).rejects.toBeInstanceOf(KycTierError)
    await expect(
      mock.issueCard({ tenant_id: tbc, customerExternalId: cus.externalId, currency: 'USD', kind: 'virtual' }),
    ).rejects.toBeInstanceOf(KycTierError)

    // Tier 0 still allows FX/transfers, and ungated account types are not blocked.
    await expect(mock.quoteFx({ tenant_id: tbc, sell: { amount: '1', currency: 'USD' }, buyCurrency: 'NGN' })).resolves.toBeDefined()
    await expect(
      mock.createAccount({ tenant_id: tbc, customerExternalId: cus.externalId, currency: 'USD', type: 'treasury' }),
    ).resolves.toMatchObject({ type: 'treasury' })
  })

  it('upgrading to Tier 1 unlocks collections and issuing', async () => {
    const mock = new MockAdapter('secret-for-tests-1234')
    const cus = await mock.createCustomer(customerInput)
    const upgraded = await mock.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: cus.externalId, targetTier: 1, tier1 })
    expect(upgraded.kycTier).toBe(1)
    await expect(
      mock.createAccount({ tenant_id: tbc, customerExternalId: cus.externalId, currency: 'NGN', type: 'virtual_account' }),
    ).resolves.toMatchObject({ type: 'virtual_account' })
    await expect(
      mock.issueCard({ tenant_id: tbc, customerExternalId: cus.externalId, currency: 'USD', kind: 'virtual' }),
    ).resolves.toMatchObject({ status: 'active' })
  })

  it('upgrades must be sequential, carry data, and move upward only', async () => {
    const mock = new MockAdapter('secret-for-tests-1234')
    const cus = await mock.createCustomer(customerInput)
    await expect(mock.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: cus.externalId, targetTier: 2, tier2 })).rejects.toThrow(/Tier 1/)
    await expect(mock.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: cus.externalId, targetTier: 1 })).rejects.toThrow(/tier1 data/)
    await mock.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: cus.externalId, targetTier: 1, tier1 })
    await expect(mock.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: cus.externalId, targetTier: 1, tier1 })).rejects.toThrow(/already/)
    const t2 = await mock.upgradeCustomerKyc({ tenant_id: tbc, customerExternalId: cus.externalId, targetTier: 2, tier2 })
    expect(t2.kycTier).toBe(2)
  })

  it('customers are tenant-scoped', async () => {
    const mock = new MockAdapter('secret-for-tests-1234')
    const cus = await mock.createCustomer(customerInput)
    const other = tenantId('someone-else')
    await expect(
      mock.upgradeCustomerKyc({ tenant_id: other, customerExternalId: cus.externalId, targetTier: 1, tier1 }),
    ).rejects.toThrow(/unknown customer/)
    await expect(
      mock.createAccount({ tenant_id: other, customerExternalId: cus.externalId, currency: 'USD', type: 'treasury' }),
    ).rejects.toThrow(/unknown customer/)
  })
})
