import restrictedData from '../config/restricted-jurisdictions.json'

export const RESTRICTED_JURISDICTIONS_LAST_CHECKED = restrictedData.last_checked

export const RESTRICTED_COUNTRY_CODES: readonly string[] = Object.freeze(
  restrictedData.restricted_country_codes.map((code) => code.toUpperCase()),
)

export const RESTRICTED_REGION_NAMES: readonly string[] = Object.freeze([
  ...restrictedData.restricted_regions,
])

const countryCodes = new Set(RESTRICTED_COUNTRY_CODES)
const regionNames = new Set(RESTRICTED_REGION_NAMES.map(normalise))

export type JurisdictionSubject = 'tenant' | 'ubo' | 'counterparty'

export interface JurisdictionUbo {
  readonly name: string
  readonly country?: string
  readonly address?: string
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
  readonly reason: 'missing_country' | 'unknown_country' | 'invalid_country' | 'restricted_country' | 'restricted_region'
  readonly value?: string
  readonly message: string
}

export interface JurisdictionScreeningResult {
  readonly allowed: boolean
  readonly reviewItems: readonly JurisdictionReviewItem[]
}

export class RestrictedJurisdictionError extends Error {
  override name = 'RestrictedJurisdictionError'
  constructor(
    readonly subject: JurisdictionSubject,
    readonly country: string,
    readonly matchedJurisdiction: string,
  ) {
    super(`${subject} country code is restricted by Maplerad: ${country}`)
  }
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

function countryCodeIssue(
  subject: JurisdictionSubject,
  country: string | undefined,
): JurisdictionReviewItem | undefined {
  if (country === undefined || country.trim() === '') {
    return {
      subject,
      reason: 'missing_country',
      message: `${subject} country is missing`,
    }
  }

  const normalized = country.trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(normalized)) {
    return {
      subject,
      reason: 'invalid_country',
      value: country,
      message: `${subject} country must be an ISO 3166-1 alpha-2 code`,
    }
  }

  if (countryCodes.has(normalized)) {
    return {
      subject,
      reason: 'restricted_country',
      value: normalized,
      message: `${subject} country code ${normalized} is restricted by Maplerad`,
    }
  }

  // This is intentionally conservative: a valid but unsupported/unknown code
  // cannot pass until the coverage catalogue is verified.
  const knownCommonCodes = new Set([
    'AT', 'AU', 'BE', 'BR', 'CA', 'CH', 'CN', 'DE', 'DK', 'EG', 'ES', 'FI',
    'FR', 'GB', 'GH', 'IE', 'IN', 'IT', 'JP', 'KE', 'LU', 'MX', 'NL', 'NO',
    'NZ', 'PL', 'PT', 'SE', 'SG', 'TR', 'TZ', 'UG', 'US', 'ZA',
  ])
  if (!knownCommonCodes.has(normalized)) {
    return {
      subject,
      reason: 'unknown_country',
      value: normalized,
      message: `${subject} country code ${normalized} is not in Aurora's verified country catalogue`,
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
    const match = RESTRICTED_REGION_NAMES.find((name) => {
      const needle = normalise(name)
      return normalise(field).includes(needle)
    })
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
  const countryIssue = countryCodeIssue('tenant', input.country)
  if (countryIssue) items.push(countryIssue)
  const tenantRegionIssue = regionIssue('tenant', [input.address, input.city, input.region])
  if (tenantRegionIssue) items.push(tenantRegionIssue)

  for (const owner of input.beneficialOwners) {
    const ownerCountryIssue = countryCodeIssue('ubo', owner.country)
    if (ownerCountryIssue) items.push(ownerCountryIssue)
    const ownerRegionIssue = regionIssue('ubo', [owner.address])
    if (ownerRegionIssue) items.push(ownerRegionIssue)
  }

  return Object.freeze({ allowed: items.length === 0, reviewItems: Object.freeze(items) })
}

export function screenCounterpartyJurisdiction(
  input: JurisdictionCounterparty,
): JurisdictionScreeningResult {
  const items: JurisdictionReviewItem[] = []
  const countryIssue = countryCodeIssue('counterparty', input.country)
  if (countryIssue) items.push(countryIssue)
  const localityIssue = regionIssue('counterparty', [input.address, input.city, input.region])
  if (localityIssue) items.push(localityIssue)
  return Object.freeze({ allowed: items.length === 0, reviewItems: Object.freeze(items) })
}

export function assertTenantJurisdictionAllowed(input: JurisdictionTenant): void {
  const result = screenTenantJurisdiction(input)
  if (!result.allowed) throw new JurisdictionReviewRequiredError(result.reviewItems)
}

export function assertCounterpartyJurisdictionAllowed(input: JurisdictionCounterparty): void {
  const result = screenCounterpartyJurisdiction(input)
  if (!result.allowed) throw new JurisdictionReviewRequiredError(result.reviewItems)
}

/**
 * Compatibility helper: accepts only ISO alpha-2 codes. Free-text country names
 * deliberately do not match and must be rejected by the screening functions.
 */
export function restrictedJurisdictionMatch(countryCode: string): string | undefined {
  const code = countryCode.trim().toUpperCase()
  return countryCodes.has(code) ? code : undefined
}
