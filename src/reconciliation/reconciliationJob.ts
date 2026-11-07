import type { TenantId } from '../core/types'

export interface ReconciliationAccount {
  readonly tenant_id: TenantId
  readonly accountExternalId: string
  readonly currency: string
  readonly providerAmountMinor: string
  readonly ledgerAmountMinor: string
}

export interface ReconciliationMismatch extends ReconciliationAccount {
  readonly differenceMinor: string
}

export interface ReconciliationProvider {
  getBalances(tenantId: TenantId): Promise<readonly ReconciliationAccount[]>
}

export interface ReconciliationResult {
  readonly tenant_id: TenantId
  readonly checkedAt: string
  readonly accountsChecked: number
  readonly mismatches: readonly ReconciliationMismatch[]
}

/**
 * Polling/reconciliation backup for webhook delivery.
 *
 * This job deliberately does not credit value or post ledger entries. A later
 * phase must verify transaction details through the provider before posting.
 */
export class ReconciliationJob {
  constructor(
    private readonly provider: ReconciliationProvider,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async run(tenantId: TenantId): Promise<ReconciliationResult> {
    const accounts = await this.provider.getBalances(tenantId)
    const mismatches = accounts
      .filter((account) => account.providerAmountMinor !== account.ledgerAmountMinor)
      .map((account) => ({
        ...account,
        differenceMinor: subtractIntegerStrings(account.providerAmountMinor, account.ledgerAmountMinor),
      }))

    return Object.freeze({
      tenant_id: tenantId,
      checkedAt: this.now().toISOString(),
      accountsChecked: accounts.length,
      mismatches: Object.freeze(mismatches),
    })
  }
}

function subtractIntegerStrings(left: string, right: string): string {
  if (!/^\d+$/.test(left) || !/^\d+$/.test(right)) {
    throw new Error('Reconciliation amounts must be non-negative integer minor-unit strings')
  }

  const a = BigInt(left)
  const b = BigInt(right)
  return (a >= b ? a - b : -(b - a)).toString()
}
