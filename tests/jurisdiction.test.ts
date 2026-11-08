import { describe, expect, it } from 'vitest'
import {
  RESTRICTED_COUNTRY_CODES,
  RESTRICTED_REGION_NAMES,
  screenCounterpartyJurisdiction,
  screenTenantJurisdiction,
} from '../src/compliance/restrictedJurisdictions'

describe('jurisdiction screening', () => {
  it('uses ISO codes and does not restrict Cyprus as a country', () => {
    expect(RESTRICTED_COUNTRY_CODES).toEqual(expect.arrayContaining(['MM', 'MK', 'CI']))
    expect(RESTRICTED_COUNTRY_CODES).not.toContain('CY')
    expect(RESTRICTED_COUNTRY_CODES).not.toContain('Burma/Myanmar')
  })

  it('keeps Northern Cyprus as a region-only manual review entry', () => {
    expect(RESTRICTED_REGION_NAMES).toContain('Northern Cyprus')
    expect(screenTenantJurisdiction({
      country: 'NG',
      city: 'Famagusta, Northern Cyprus',
      beneficialOwners: [],
    }).reviewItems.some((item) => item.reason === 'restricted_region')).toBe(true)
  })

  it('blocks restricted countries for tenant, UBO, and counterparty', () => {
    expect(screenTenantJurisdiction({
      country: 'NG',
      beneficialOwners: [{ name: 'Owner', country: 'MM' }],
    }).allowed).toBe(false)
    expect(screenCounterpartyJurisdiction({ country: 'MK' }).allowed).toBe(false)
  })

  it('fails closed while coverage is unverified, including NG', () => {
    expect(screenTenantJurisdiction({ country: 'NG', beneficialOwners: [] }).reviewItems[0]?.reason).toBe('unknown_country')
  })

  it('blocks missing, free-text, and malformed country values', () => {
    expect(screenTenantJurisdiction({ beneficialOwners: [] }).allowed).toBe(false)
    expect(screenTenantJurisdiction({ country: 'Nigeria', beneficialOwners: [] }).allowed).toBe(false)
    expect(screenTenantJurisdiction({ country: 'G1', beneficialOwners: [] }).allowed).toBe(false)
  })

  it('blocks unknown ISO codes', () => {
    expect(screenCounterpartyJurisdiction({ country: 'ZZ' }).allowed).toBe(false)
  })

  it('checks counterparty locality fields for restricted regions', () => {
    expect(screenCounterpartyJurisdiction({
      country: 'NG',
      address: 'Northern Cyprus district',
    }).reviewItems.some((item) => item.reason === 'restricted_region')).toBe(true)
  })

  it('checks every UBO country and locality', () => {
    const result = screenTenantJurisdiction({
      country: 'NG',
      beneficialOwners: [
        {
          name: 'Owner',
          country: 'GB',
          address: 'South Ossetia',
        },
      ],
    })

    expect(result.allowed).toBe(false)
    expect(result.reviewItems.some((item) => item.subject === 'ubo')).toBe(true)
  })
})
