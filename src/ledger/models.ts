import type { AccountType } from '../adapters/types'
import type { KycTier } from '../core/kyc/kycTier'
import type { Direction, ISODateTime, ProviderName, TenantRecord } from '../core/types'

/**
 * TypeScript mirrors of the custom ERPNext DocTypes (brief §6).
 * No ERPNext calls exist in Phase 1; these fix the shape so later phases cannot drift.
 */

/** Provider-side customer for a tenant, with its KYC tier (Maplerad: 0/1/2). */
export interface AuroraProviderCustomer extends TenantRecord {
  readonly provider: ProviderName
  readonly external_id: string
  readonly first_name: string
  readonly last_name: string
  readonly email: string
  readonly country: string
  readonly kyc_tier: KycTier
  readonly kyc_status: 'pending' | 'approved' | 'rejected'
  readonly created_at: ISODateTime
}

export interface AuroraProviderAccount extends TenantRecord {
  readonly provider: ProviderName
  readonly external_id: string
  readonly currency: string
  readonly country: string
  /** 'treasury' and 'spend' exist because Maplerad splits USD into TREASURY and SPEND wallets. */
  readonly type: AccountType
  readonly erpnext_account?: string
  readonly status: 'active' | 'frozen' | 'closed'
}

export interface AuroraTransaction extends TenantRecord {
  readonly provider: ProviderName
  readonly external_id: string
  readonly direction: Direction
  readonly amount: string
  readonly currency: string
  readonly fee: string
  readonly status: 'pending' | 'settled' | 'failed' | 'suspense'
  readonly raw_payload_hash: string
  readonly linked_payment_entry?: string
  readonly linked_journal_entry?: string
}

export interface AuroraFxQuote extends TenantRecord {
  readonly quote_reference: string
  readonly pair: string
  readonly rate: string
  readonly fee: string
  readonly expiry: ISODateTime
  readonly executed: boolean
  readonly linked_journal?: string
}

export interface AuroraPayout extends TenantRecord {
  readonly counterparty: string
  readonly amount: string
  readonly currency: string
  readonly purpose_category: string
  readonly approvers: readonly string[]
  readonly status: 'draft' | 'pending_approval' | 'approved' | 'sent' | 'failed' | 'rejected'
  readonly provider_reference?: string
  /** Outward-facing reference. Neutral text only; no source identifiers. */
  readonly external_reference: string
}

/** Port for the system of record. Implemented in Phase 2+. */
export interface ErpNextPort {
  ensureCompanyForTenant(tenant: TenantRecord & { legalName: string; baseCurrency: string }): Promise<string>
  mirrorProviderAccount(account: AuroraProviderAccount): Promise<string>
}
