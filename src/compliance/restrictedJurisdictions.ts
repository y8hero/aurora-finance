import restrictedData from '../config/restricted-jurisdictions.json'
import coverageData from '../config/maplerad-country-coverage.json'

interface MapleradCoverageConfig {
  readonly source: string
  readonly last_checked: string
  readonly verified: boolean
  readonly recheck_before_launch: boolean
  readonly candidate_codes: readonly string[]
  readonly verified_codes: readonly string[]
}

const coverage = coverageData as MapleradCoverageConfig

export const RESTRICTED_JURISDICTIONS_LAST_CHECKED = restrictedData.last_checked

export const RESTRICTED_COUNTRY_CODES: readonly string[] = Object.freeze(
  restrictedData.restricted_country_codes.map((code) => code.toUpperCase()),
)

export const RESTRICTED_REGION_NAMES: readonly string[] = Object.freeze([
  ...restrictedData.restricted_regions,
])

const restrictedCountryCodes = new Set(RESTRICTED_COUNTRY_CODES)
const restrictedRegionNames = new Set(RESTRICTED_REGION_NAMES.map(normalise))
const verifiedCoverageCodes = new Set(
  coverage.verified_codes.map((code) => code.toUpperCase()),
)

export type JurisdictionSubject = 'tenant' | 'ubo' | 'counterparty'

export interface JurisdictionUbo {
  readonly name: string
  readonly country?: string
  readonly address?: string
  readonly city?: string
  readonly region?: string
}

export interface JurisdictionTenant {
  readonly country?: string
  readonly address?: string
  readonly city?: string
  readonly region?: string
  readonly beneficialOwners: readonly JurisdictionUbo[]
}

export interface JurisdictionCounterparty {
  readonly country?: string
  readonly address?: string
  readonly city?: string
  readonly region?: string
}

export interface JurisdictionReviewItem {
  readonly subject: JurisdictionSubject
  readonly reason:
    | 'missing_country'
    | 'unknown_country'
    | 'invalid_country'
    | 'restricted_country'
    | 'restricted_region'
  readonly value?: string
  readonly message: string
}

export interface JurisdictionScreeningResult {
  readonly allowed: boolean
  readonly reviewItems: readonly JurisdictionReviewItem[]
}

export class JurisdictionReviewRequiredError extends Error {
  override name = 'JurisdictionReviewRequiredError'

  constructor(readonly items: readonly JurisdictionReviewItem[]) {
    super(`Jurisdiction review required: ${items.map((item) => item.message).join('; ')}`)
  }
}

export function normalise(value: string): string {
  return value.trim().toLocaleLowerCase('en-US').replace(/\s+/g, ' ')
}

function countryIssue(
  subject: JurisdictionSubject,
  country: string | undefined,
): JurisdictionReviewItem | undefined {
  if (!country || country.trim() === '') {
    return {
      subject,
      reason: 'missing_country',
      message: `${subject} country is missing`,
    }
  }

  const code = country.trim().toUpperCase()

  if (!/^[A-Z]{2}$/.test(code)) {
    return {
      subject,
      reason: 'invalid_country',
      value: country,
      message: `${subject} country must be an ISO 3166-1 alpha-2 code`,
    }
  }

  if (restrictedCountryCodes.has(code)) {
    return {
      subject,
      reason: 'restricted_country',
      value: code,
      message: `${subject} country code ${code} is restricted by Maplerad`,
    }
  }

  if (!coverage.verified || !verifiedCoverageCodes.has(code)) {
    return {
      subject,
      reason: 'unknown_country',
      value: code,
      message: `${subject} country code ${code} is not in Maplerad's verified coverage list`,
    }
  }

  return undefined
}

function regionIssue(
  subject: JurisdictionSubject,
  fields: readonly (string | undefined)[],
): JurisdictionReviewItem | undefined {
  for (const field of fields) {
    if (!field) continue

    const match = RESTRICTED_REGION_NAMES.find((name) =>
      normalise(field).includes(normalise(name)),
    )

    if (match) {
      return {
        subject,
        reason: 'restricted_region',
        value: field,
        message: `${subject} address or locality may reference restricted region ${match}; manual review required`,
      }
    }
  }

  return undefined
}

export function screenTenantJurisdiction(input: JurisdictionTenant): JurisdictionScreeningResult {
  const items: JurisdictionReviewItem[] = []

  const tenantCountry = countryIssue('tenant', input.country)
  if (tenantCountry) items.push(tenantCountry)

  const tenantRegion = regionIssue('tenant', [input.address, input.city, input.region])
  if (tenantRegion) items.push(tenantRegion)

  for (const owner of input.beneficialOwners) {
    const ownerCountry = countryIssue('ubo', owner.country)
    if (ownerCountry) items.push(ownerCountry)

    const ownerRegion = regionIssue('ubo', [owner.address, owner.city, owner.region])
    if (ownerRegion) items.push(ownerRegion)
  }

  return Object.freeze({
    allowed: items.length === 0,
    reviewItems: Object.freeze(items),
  })
}

export function screenCounterpartyJurisdiction(
  input: JurisdictionCounterparty,
): JurisdictionScreeningResult {
  const items: JurisdictionReviewItem[] = []

  const country = countryIssue('counterparty', input.country)
  if (country) items.push(country)

  const region = regionIssue('counterparty', [input.address, input.city, input.region])
  if (region) items.push(region)

  return Object.freeze({
    allowed: items.length === 0,
    reviewItems: Object.freeze(items),
  })
}

export function assertTenantJurisdictionAllowed(input: JurisdictionTenant): void {
  const result = screenTenantJurisdiction(input)
  if (!result.allowed) throw new JurisdictionReviewRequiredError(result.reviewItems)
}

export function assertCounterpartyJurisdictionAllowed(input: JurisdictionCounterparty): void {
  const result = screenCounterpartyJurisdiction(input)
  if (!result.allowed) throw new JurisdictionReviewRequiredError(result.reviewItems)
}

export function restrictedJurisdictionMatch(countryCode: string): string | undefined {
  const code = countryCode.trim().toUpperCase()
  return restrictedCountryCodes.has(code) ? code : undefined
}
