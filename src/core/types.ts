/** Branded tenant identifier. Every record and every query must carry one. */
export type TenantId = string & { readonly __brand: 'TenantId' }

const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{1,63}$/i

export function tenantId(raw: string): TenantId {
  if (typeof raw !== 'string' || !TENANT_ID_PATTERN.test(raw)) {
    throw new Error(`Invalid tenant_id: ${JSON.stringify(raw)}`)
  }
  return raw as TenantId
}

/** Platform-level actions are recorded under this tenant. */
export const PLATFORM_TENANT: TenantId = tenantId('platform')

export interface TenantRecord {
  readonly tenant_id: TenantId
}

export type Region = 'EU' | 'US' | 'AFRICA'
export type ProviderName = 'maplerad' | 'circle' | 'mock'

/**
 * Monetary amounts are integer minor units represented as decimal strings.
 *
 * Examples:
 * - USD 100.00 => amount "10000", currency "USD"
 * - NGN 100.00 => amount "10000", currency "NGN"
 *
 * The `amount` property is retained for API compatibility with the Phase 1
 * skeleton; it must contain minor units, never a decimal major-unit amount.
 */
export interface Money {
  readonly amount: string
  readonly currency: string
}

export function isIntegerMinorUnitAmount(amount: string): boolean {
  return /^\d+$/.test(amount)
}

export function assertIntegerMinorUnitAmount(money: Money): void {
  if (!isIntegerMinorUnitAmount(money.amount)) {
    throw new Error(
      `Money amount must be a non-negative integer minor-unit string; received ${JSON.stringify(money.amount)}`,
    )
  }
  if (!/^[A-Z0-9]{3,10}$/.test(money.currency)) {
    throw new Error(`Invalid currency or asset code: ${JSON.stringify(money.currency)}`)
  }
}

export type Direction = 'in' | 'out'
export type ISODateTime = string
