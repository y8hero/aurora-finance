import type { KycTier } from './kyc/kycTier'
import type { TenantId } from './types'

export class CustomerConflictError extends Error {
  override name = 'CustomerConflictError'
}

export class ValidationError extends Error {
  override name = 'ValidationError'
}

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

export function normalizeCustomerInput(input: CustomerCreateInput): CustomerCreateInput {
  return {
    ...input,
    first_name: input.first_name.trim(),
    last_name: input.last_name.trim(),
    email: input.email.trim().toLowerCase(),
    ...(input.external_ref !== undefined
      ? { external_ref: input.external_ref.trim() }
      : {}),
  }
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function validateCustomerCursor(cursor: string | undefined): void {
  if (cursor !== undefined && !UUID_PATTERN.test(cursor)) {
    throw new ValidationError('cursor must be a UUID')
  }
}
