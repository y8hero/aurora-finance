/** Branded tenant identifier. Every record and every query must carry one. */
export type TenantId = string & { readonly __brand: 'TenantId' }

const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{1,63}$/i

export function tenantId(raw: string): TenantId {
  if (typeof raw !== 'string' || !TENANT_ID_PATTERN.test(raw)) {
    throw new Error(`Invalid tenant_id: ${JSON.stringify(raw)}`)
  }
  return raw as TenantId
}

/**
 * Fixed database-backed system tenant. This UUID is seeded by migration 001
 * and is used for platform-level audit events such as unresolved webhooks.
 */
export const PLATFORM_TENANT =
  '00000000-0000-0000-0000-000000000001' as TenantId

export interface TenantRecord {
  readonly tenant_id: TenantId
}

export type Region = 'EU' | 'US' | 'AFRICA'
export type ProviderName = 'maplerad' | 'circle' | 'mock'

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
