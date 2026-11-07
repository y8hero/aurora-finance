import type { KycTier } from '../core/kyc/kycTier'
import type { Direction, Money, ProviderName, Region, TenantId } from '../core/types'

export type WebhookHeaders = Readonly<Record<string, string | string[] | undefined>>

export interface CustomerInput {
  readonly tenant_id: TenantId
  readonly legalName: string
  readonly firstName: string
  readonly lastName: string
  readonly email: string
  readonly country: string
  readonly region: Region
  readonly beneficialOwners: readonly { name: string; role: string; country?: string; address?: string }[]
  readonly sourceOfFundsRef: string
}

export interface ProviderCustomer {
  readonly tenant_id: TenantId
  readonly provider: ProviderName
  readonly externalId: string
  readonly kycStatus: 'pending' | 'approved' | 'rejected'
  readonly kycTier: KycTier
}

export interface KycTier1Data {
  readonly phone: string
  readonly dateOfBirth: string
  readonly identificationNumber: string
  readonly homeAddress: string
}

export interface KycTier2Data {
  readonly identityDocument: { readonly type: string; readonly number: string }
}

export interface KycUpgradeInput {
  readonly tenant_id: TenantId
  readonly customerExternalId: string
  readonly targetTier: 1 | 2
  readonly tier1?: KycTier1Data
  readonly tier2?: KycTier2Data
}

export type AccountType = 'virtual_account' | 'wallet' | 'card' | 'treasury' | 'spend'

export interface AccountInput {
  readonly tenant_id: TenantId
  readonly customerExternalId: string
  readonly currency: string
  readonly type: AccountType
  readonly chain?: string
}

export interface ProviderAccount {
  readonly tenant_id: TenantId
  readonly provider: ProviderName
  readonly externalId: string
  readonly currency: string
  readonly type: AccountType
  readonly address?: string
}

export interface Balance {
  readonly tenant_id: TenantId
  readonly accountExternalId: string
  readonly available: Money
}

export interface FxInput {
  readonly tenant_id: TenantId
  readonly sell: Money
  readonly buyCurrency: string
}

export interface FxQuote {
  readonly tenant_id: TenantId
  readonly quoteRef: string
  readonly sell: Money
  readonly buy: Money
  readonly rate: string
  readonly fee: Money
  readonly expiresAt: string
}

export interface FxResult {
  readonly tenant_id: TenantId
  readonly quoteRef: string
  readonly executedAt: string
  readonly providerRef: string
}

export interface PayoutInput {
  readonly tenant_id: TenantId
  readonly counterpartyId: string
  readonly counterpartyCountry?: string
  readonly amount: Money
  readonly reference: string
  readonly purposeCategory: string
}

export interface PayoutResult {
  readonly tenant_id: TenantId
  readonly providerRef: string
  readonly status: 'pending' | 'sent' | 'failed'
}

export interface CardInput {
  readonly tenant_id: TenantId
  readonly customerExternalId: string
  readonly currency: string
  readonly kind: 'virtual' | 'physical'
}

export interface Card {
  readonly tenant_id: TenantId
  readonly provider: ProviderName
  readonly externalId: string
  readonly last4: string
  readonly status: 'active' | 'frozen' | 'terminated'
}

export interface ProviderEvent {
  readonly provider: ProviderName
  readonly eventId: string
  readonly eventType: string
  readonly direction?: Direction
  readonly occurredAt?: string
  readonly payload: unknown
}

export interface ProviderAdapter {
  readonly name: ProviderName
  checkAuth(): Promise<void>
  createCustomer?(input: CustomerInput): Promise<ProviderCustomer>
  upgradeCustomerKyc?(input: KycUpgradeInput): Promise<ProviderCustomer>
  createAccount?(input: AccountInput): Promise<ProviderAccount>
  getBalances(tenantId: TenantId): Promise<Balance[]>
  quoteFx?(input: FxInput): Promise<FxQuote>
  executeFx?(tenantId: TenantId, quoteRef: string): Promise<FxResult>
  createPayout?(input: PayoutInput, idempotencyKey: string): Promise<PayoutResult>
  issueCard?(input: CardInput): Promise<Card>
  parseWebhook(rawBody: string, headers: WebhookHeaders): Promise<ProviderEvent>
}
