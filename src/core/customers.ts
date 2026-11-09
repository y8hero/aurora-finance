import type { KycTier } from './kyc/kycTier'
import type { TenantId } from './types'

export interface CustomerRecord {
  readonly id: string
  readonly tenant_id: TenantId
  readonly external_ref?: string
  readonly first_name: string
  readonly last_name: string
  readonly email: string
  readonly country: string
  readonly kyc_tier: KycTier
  readonly status: string
  readonly created_at: string
}

export interface CustomerCreateInput {
  readonly external_ref?: string
  readonly first_name: string
  readonly last_name: string
  readonly email: string
  readonly country: string
  readonly kyc_tier?: KycTier
  readonly status?: string
}

export interface CustomerRepository {
  create(tenantId: TenantId, input: CustomerCreateInput): Promise<CustomerRecord>
  get(tenantId: TenantId, id: string): Promise<CustomerRecord | undefined>
  getByExternalRef(tenantId: TenantId, ref: string): Promise<CustomerRecord | undefined>
  list(tenantId: TenantId, limit: number, cursor?: string): Promise<readonly CustomerRecord[]>
}
