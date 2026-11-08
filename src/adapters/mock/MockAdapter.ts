import { randomUUID } from 'node:crypto'
import { canonicalJson } from '../../core/canonical'
import { IdempotencyStore } from '../../core/idempotency'
import { assertKycTierAllows, featureForAccountType } from '../../core/kyc/kycTier'
import type { TenantId, ProviderName } from '../../core/types'
import { HmacSha256Verifier } from '../../webhooks/signature'
import type { WebhookParser } from '../../webhooks/receiver'
import type {
  AccountInput,
  Balance,
  Card,
  CardInput,
  CustomerInput,
  FxInput,
  FxQuote,
  FxResult,
  KycUpgradeInput,
  PayoutInput,
  PayoutResult,
  ProviderAccount,
  ProviderAdapter,
  ProviderCustomer,
  ProviderEvent,
  WebhookHeaders,
} from '../types'

export const MOCK_SIGNATURE_HEADER = 'x-mock-signature'
export const MOCK_TIMESTAMP_HEADER = 'x-mock-timestamp'

export interface MockWebhookBody {
  id: string
  type: string
  provider_customer_id: string
  occurred_at?: string
  data?: unknown
}

export const mockWebhookParser: WebhookParser = {
  provider: 'mock',
  parse(rawBody) {
    const body = JSON.parse(rawBody) as Partial<MockWebhookBody>

    if (
      typeof body.id !== 'string' ||
      typeof body.type !== 'string' ||
      typeof body.provider_customer_id !== 'string'
    ) {
      throw new Error('mock webhook requires id, type, and provider_customer_id')
    }

    return {
      eventId: body.id,
      eventType: body.type,
      providerCustomerId: body.provider_customer_id,
      ...(body.occurred_at ? { occurredAt: body.occurred_at } : {}),
    }
  },
}

export function createMockVerifier(secret: string, now?: () => number): HmacSha256Verifier {
  return new HmacSha256Verifier({
    provider: 'mock',
    secret,
    signatureHeader: MOCK_SIGNATURE_HEADER,
    timestampHeader: MOCK_TIMESTAMP_HEADER,
    toleranceSeconds: 300,
    ...(now ? { now } : {}),
  })
}

export class MockAdapter implements ProviderAdapter {
  readonly name = 'mock' as const
  readonly calls: { method: string; args: unknown[] }[] = []
  readonly verifier: HmacSha256Verifier

  private readonly customers = new Map<TenantId, Map<string, ProviderCustomer>>()
  private readonly customerTenants = new Map<string, TenantId>()
  private readonly accounts = new Map<TenantId, ProviderAccount[]>()
  private readonly quotes = new Map<string, FxQuote>()
  private readonly idempotency = new IdempotencyStore()
  private readonly now: () => Date

  constructor(webhookSecret: string, now: () => Date = () => new Date()) {
    this.verifier = createMockVerifier(webhookSecret, () => Math.floor(now().getTime() / 1000))
    this.now = now
  }

  readonly tenantResolver = {
    resolve: async (
      _provider: ProviderName,
      providerCustomerId: string,
    ): Promise<TenantId | undefined> => this.customerTenants.get(providerCustomerId),
  }

  private record(method: string, ...args: unknown[]): void {
    this.calls.push({ method, args })
  }

  private customerFor(tenantId: TenantId, externalId: string): ProviderCustomer {
    const customer = this.customers.get(tenantId)?.get(externalId)
    if (!customer) throw new Error(`unknown customer ${externalId} for tenant ${tenantId}`)
    return customer
  }

  async checkAuth(): Promise<void> {
    this.record('checkAuth')
  }

  async createCustomer(input: CustomerInput): Promise<ProviderCustomer> {
    this.record('createCustomer', input)

    const customer: ProviderCustomer = {
      tenant_id: input.tenant_id,
      provider: 'mock',
      externalId: `cus_${randomUUID()}`,
      kycStatus: 'approved',
      kycTier: 0,
    }

    const bucket = this.customers.get(input.tenant_id) ?? new Map<string, ProviderCustomer>()
    bucket.set(customer.externalId, customer)
    this.customers.set(input.tenant_id, bucket)
    this.customerTenants.set(customer.externalId, input.tenant_id)

    return customer
  }

  async upgradeCustomerKyc(input: KycUpgradeInput): Promise<ProviderCustomer> {
    this.record('upgradeCustomerKyc', input)

    const existing = this.customerFor(input.tenant_id, input.customerExternalId)

    if (input.targetTier <= existing.kycTier) {
      throw new Error(`customer is already at tier ${existing.kycTier}`)
    }

    if (input.targetTier === 2 && existing.kycTier < 1) {
      throw new Error('Tier 1 must be completed before Tier 2; tier1 data is required')
    }

    if (input.targetTier === 1 && !input.tier1) {
      throw new Error('tier1 data is required for Tier 1 upgrade')
    }

    if (input.targetTier === 2 && !input.tier2) {
      throw new Error('tier2 data is required for Tier 2 upgrade')
    }

    const updated: ProviderCustomer = {
      ...existing,
      kycTier: input.targetTier,
    }

    this.customers.get(input.tenant_id)!.set(input.customerExternalId, updated)
    return updated
  }

  async createAccount(input: AccountInput): Promise<ProviderAccount> {
    this.record('createAccount', input)

    const customer = this.customerFor(input.tenant_id, input.customerExternalId)
    const feature = featureForAccountType(input.type)

    if (feature) {
      assertKycTierAllows({
        tenant_id: input.tenant_id,
        customerExternalId: input.customerExternalId,
        kycTier: customer.kycTier,
        feature,
      })
    }

    const account: ProviderAccount = {
      tenant_id: input.tenant_id,
      provider: 'mock',
      externalId: `acc_${randomUUID()}`,
      currency: input.currency,
      type: input.type,
    }

    const accounts = this.accounts.get(input.tenant_id) ?? []
    accounts.push(account)
    this.accounts.set(input.tenant_id, accounts)
    return account
  }

  async getBalances(tenantId: TenantId): Promise<Balance[]> {
    this.record('getBalances', tenantId)

    return (this.accounts.get(tenantId) ?? []).map((account) => ({
      tenant_id: tenantId,
      accountExternalId: account.externalId,
      available: { amount: '0', currency: account.currency },
    }))
  }

  async quoteFx(input: FxInput): Promise<FxQuote> {
    this.record('quoteFx', input)

    const quote: FxQuote = {
      tenant_id: input.tenant_id,
      quoteRef: `fxq_${randomUUID()}`,
      sell: input.sell,
      buy: { amount: input.sell.amount, currency: input.buyCurrency },
      rate: '1',
      fee: { amount: '0', currency: input.sell.currency },
      expiresAt: new Date(this.now().getTime() + 60_000).toISOString(),
    }

    this.quotes.set(quote.quoteRef, quote)
    return quote
  }

  async executeFx(tenantId: TenantId, quoteRef: string): Promise<FxResult> {
    this.record('executeFx', tenantId, quoteRef)

    const quote = this.quotes.get(quoteRef)
    if (!quote || quote.tenant_id !== tenantId) {
      throw new Error('unknown quote for tenant')
    }

    if (new Date(quote.expiresAt) < this.now()) {
      throw new Error('quote expired')
    }

    return {
      tenant_id: tenantId,
      quoteRef,
      executedAt: this.now().toISOString(),
      providerRef: `fx_${randomUUID()}`,
    }
  }

  async createPayout(input: PayoutInput, idempotencyKey: string): Promise<PayoutResult> {
    return this.idempotency.run(
      input.tenant_id,
      idempotencyKey,
      canonicalJson(input),
      async () => {
        this.record('createPayout', input, idempotencyKey)

        return {
          tenant_id: input.tenant_id,
          providerRef: `po_${randomUUID()}`,
          status: 'pending',
        }
      },
    )
  }

  async issueCard(input: CardInput): Promise<Card> {
    this.record('issueCard', input)

    const customer = this.customerFor(input.tenant_id, input.customerExternalId)

    assertKycTierAllows({
      tenant_id: input.tenant_id,
      customerExternalId: input.customerExternalId,
      kycTier: customer.kycTier,
      feature: 'issuing',
    })

    return {
      tenant_id: input.tenant_id,
      provider: 'mock',
      externalId: `card_${randomUUID()}`,
      last4: '4242',
      status: 'active',
    }
  }

  async parseWebhook(rawBody: string, headers: WebhookHeaders): Promise<ProviderEvent> {
    const verification = this.verifier.verify(rawBody, headers)
    if (!verification.ok) {
      throw new Error(`webhook signature invalid: ${verification.reason}`)
    }

    const parsed = mockWebhookParser.parse(rawBody)
    const body = JSON.parse(rawBody) as MockWebhookBody

    return {
      provider: 'mock',
      eventId: parsed.eventId,
      eventType: parsed.eventType,
      payload: body.data,
      ...(parsed.occurredAt ? { occurredAt: parsed.occurredAt } : {}),
    }
  }

  signHeaders(rawBody: string, unixSeconds?: number): WebhookHeaders {
    const timestamp = String(unixSeconds ?? Math.floor(this.now().getTime() / 1000))

    return {
      [MOCK_SIGNATURE_HEADER]: this.verifier.sign(rawBody, timestamp),
      [MOCK_TIMESTAMP_HEADER]: timestamp,
      'content-type': 'application/json',
    }
  }
}
