import type { AccountType } from '../../adapters/types'
import type { TenantId } from '../types'

/**
 * Maplerad KYC tiers. VERIFIED from https://maplerad.dev/docs/customers (2026-11-07).
 *
 * | Tier | Data required                                              | Unlocks                          |
 * | 0    | first name, last name, email                               | Bills, FX, Transfers             |
 * | 1    | phone, date of birth, ID number (BVN/SSN), home address    | Collections, Issuing (+ Tier 0)  |
 * | 2    | identity document (e.g. NIN)                               | All services                     |
 *
 * A tenant's customer cannot get virtual accounts (Collections) or cards (Issuing) below Tier 1.
 */
export type KycTier = 0 | 1 | 2

export const KYC_TIERS: readonly KycTier[] = Object.freeze([0, 1, 2] as const)

export function isKycTier(v: unknown): v is KycTier {
  return v === 0 || v === 1 || v === 2
}

export type KycGatedFeature = 'bills' | 'fx' | 'transfers' | 'collections' | 'issuing'

export const REQUIRED_KYC_TIER: Readonly<Record<KycGatedFeature, KycTier>> = Object.freeze({
  bills: 0,
  fx: 0,
  transfers: 0,
  collections: 1,
  issuing: 1,
})

/** Human-readable list of what each tier requires (Aurora-internal names; Maplerad field names UNVERIFIED for upgrades). */
export const KYC_TIER_DATA_REQUIRED: Readonly<Record<KycTier, readonly string[]>> = Object.freeze({
  0: Object.freeze(['first_name', 'last_name', 'email']),
  1: Object.freeze(['phone', 'date_of_birth', 'identification_number (e.g. BVN or SSN)', 'home_address']),
  2: Object.freeze(['identity_document (e.g. NIN)']),
})

export function canUseFeature(kycTier: KycTier, feature: KycGatedFeature): boolean {
  return kycTier >= REQUIRED_KYC_TIER[feature]
}

/**
 * Which gated feature an account type belongs to.
 * UNVERIFIED: which tier unlocks the Wallets endpoints (treasury/spend/wallet) — not in the tier table, so not gated here.
 */
export function featureForAccountType(type: AccountType): KycGatedFeature | undefined {
  switch (type) {
    case 'virtual_account':
      return 'collections'
    case 'card':
      return 'issuing'
    default:
      return undefined
  }
}

export class KycTierError extends Error {
  override name = 'KycTierError'
  constructor(
    readonly tenant_id: TenantId,
    readonly customerExternalId: string,
    readonly feature: KycGatedFeature,
    readonly requiredTier: KycTier,
    readonly actualTier: KycTier,
  ) {
    super(
      `Customer ${customerExternalId} (tenant ${tenant_id}) is KYC tier ${actualTier}; "${feature}" requires tier ${requiredTier}`,
    )
  }
}

export interface KycCheckInput {
  readonly tenant_id: TenantId
  readonly customerExternalId: string
  readonly kycTier: KycTier
  readonly feature: KycGatedFeature
}

export function assertKycTierAllows(input: KycCheckInput): void {
  const required = REQUIRED_KYC_TIER[input.feature]
  if (input.kycTier < required) {
    throw new KycTierError(input.tenant_id, input.customerExternalId, input.feature, required, input.kycTier)
  }
}
