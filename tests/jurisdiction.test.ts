import { describe, expect, it } from 'vitest'
import {
  RESTRICTED_COUNTRY_CODES,
  RESTRICTED_REGION_NAMES,
  JurisdictionReviewRequiredError,
  assertCounterpartyJurisdictionAllowed,
  assertTenantJurisdictionAllowed,
  screenCounterpartyJurisdiction,
  screenTenantJurisdiction,
} from '../src/compliance/restrictedJurisdictions'

describe('fail-closed ISO jurisdiction screening', () => {
  it('maps representative restricted names to ISO codes', () => {
    expect(RESTRICTED_COUNTRY_CODES).toEqual(expect.arrayContaining(['MM', 'MK', 'CI']))
    expect(RESTRICTED_COUNTRY_CODES).not.toContain('Burma/Myanmar')
  })

  it('keeps non-ISO entries as manual-review regions', () => {
    expect(RESTRICTED_REGION_NAMES).toEqual(
      expect.arrayContaining([
        'Abkhazia',
        'Nagorno-Karabakh',
        'Northern Cyprus',
        'Somaliland',
        'South Ossetia',
        'Sahrawi Arab Democratic Republic',
      ]),
    )
  })

  it('blocks restricted country codes for tenant, every UBO, and counterparty', () => {
    expect(screenTenantJurisdiction({
      country: 'GB',
      beneficialOwners: [{ name: 'Owner', country: 'MM' }],
    }).allowed).toBe(false)

    expect(screenCounterpartyJurisdiction({ country: 'MK' }).allowed).toBe(false)
    expect(screenTenantJurisdiction({ country: 'CI', beneficialOwners: [] }).allowed).toBe(false)
  })

  it('blocks free-text country names and missing countries', () => {
    expect(screenTenantJurisdiction({ country: 'United Kingdom', beneficialOwners: [] }).allowed).toBe(false)
    expect(screenTenantJurisdiction({ beneficialOwners: [] }).allowed).toBe(false)
    expect(screenCounterpartyJurisdiction({ country: '' }).allowed).toBe(false)
  })

  it('blocks unknown and malformed ISO codes rather than passing', () => {
    expect(screenTenantJurisdiction({ country: 'ZZ', beneficialOwners: [] }).reviewItems[0]?.reason).toBe('unknown_country')
    expect(screenTenantJurisdiction({ country: 'G1', beneficialOwners: [] }).reviewItems[0]?.reason).toBe('invalid_country')
  })

  it('flags restricted regions found in address, city, or region fields', () => {
    const result = screenTenantJurisdiction({
      country: 'GB',
      city: 'Famagusta, Northern Cyprus',
      region: 'Northern Cyprus',
      address: '1 Example Road',
      beneficialOwners: [],
    })
    expect(result.allowed).toBe(false)
    expect(result.reviewItems.some((item) => item.reason === 'restricted_region')).toBe(true)
  })

  it('assertions fail closed with a review item', () => {
    expect(() => assertTenantJurisdictionAllowed({
      country: 'GB',
      beneficialOwners: [{ name: 'Owner' }],
    })).toThrow(JurisdictionReviewRequiredError)

    expect(() => assertCounterpartyJurisdictionAllowed({ country: 'SO' })).toThrow(/restricted/)
  })

  it('allows a verified, non-restricted ISO code with no restricted locality text', () => {
    expect(screenTenantJurisdiction({
      country: 'GB',
      beneficialOwners: [{ name: 'Owner', country: 'US' }],
    })).toEqual({ allowed: true, reviewItems: [] })
  })
})
