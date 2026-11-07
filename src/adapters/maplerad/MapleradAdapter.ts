import { Secret } from '../../config/env'
import type { TenantId } from '../../core/types'
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
import { unverified } from '../unverified'
import { MapleradWebhookVerifier } from './MapleradWebhookVerifier'
import type { VerifyContext } from '../../webhooks/signature'

/**
 * Maplerad adapter — Phase 1. NO LIVE CALLS. No HTTP client is wired and `maplerad-node` is not installed.
 *
 * VERIFIED (maplerad.dev, 2026-11-07):
 *  - One base URL `https://api.maplerad.com` for sandbox and live; the key decides the environment.
 *  - Auth: `Authorization: Bearer <SECRET_KEY>`. HTTPS only. 401 on bad auth; production needs IP whitelisting (403).
 *  - Create customer (Tier 0): `POST /v1/customers` with `first_name`, `last_name`, `email`, `country`. Response schema UNVERIFIED.
 *  - KYC tiers 0/1/2 (see core/kyc/kycTier.ts).
 *  - Webhook signatures: Svix-style (see MapleradWebhookVerifier.ts).
 *  - USD split into SPEND (cards only) and TREASURY (everything else) wallets; wallet-funding endpoint moves funds.
 *  - FX is quote, then exchange by quote reference.
 *
 * UNVERIFIED (methods below throw `UnverifiedError`): response schemas, rate limits, error formats, webhook event
 * names/payloads, country/currency coverage, upgrade-endpoint fields, which tier unlocks Wallets, Solana per asset.
 *
 * WARNING: docs.maple.inc / api.maple.inc belong to a different company (restaurant ordering). NOT Maplerad.
 */
export const MAPLERAD_BASE_URL = 'https://api.maplerad.com'
export const MAPLERAD_DASHBOARD_URL = 'https://app.maplerad.com'

export const MAPLERAD_PATHS = Object.freeze({
  /** VERIFIED: POST, Tier 0 customer. */
  createCustomer: '/v1/customers',
})

export const MAPLERAD_API_AREAS = [
  'Customer',
  'Collections',
  'Transfers',
  'Bills',
  'Wallets',
  'Issuing',
  'Identity',
  'Transactions',
  'Counterparty',
  'FX',
  'Institutions',
  'Misc',
] as const

export type MapleradApiArea = (typeof MAPLERAD_API_AREAS)[number]

/** USD wallet split (since April 2026). Each maps to its own ledger account. */
export type MapleradUsdWalletKind = 'SPEND' | 'TREASURY'

/** VERIFIED header format. The only place a Maplerad secret is ever revealed. */
export function mapleradAuthorizationHeader(secret: Secret): string {
  return `Bearer ${secret.reveal()}`
}

/** VERIFIED required body for POST /v1/customers. */
export interface MapleradCreateCustomerBody {
  readonly first_name: string
  readonly last_name: string
  readonly email: string
  readonly country: string
}

export class MapleradInputError extends Error {
  override name = 'MapleradInputError'
}

export function toMapleradCreateCustomerBody(input: CustomerInput): MapleradCreateCustomerBody {
  const required: Record<keyof MapleradCreateCustomerBody, string> = {
    first_name: input.firstName,
    last_name: input.lastName,
    email: input.email,
    country: input.country,
  }
  for (const [field, value] of Object.entries(required)) {
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new MapleradInputError(`Maplerad create-customer requires non-empty "${field}"`)
    }
  }
  return {
    first_name: input.firstName.trim(),
    last_name: input.lastName.trim(),
    email: input.email.trim(),
    country: input.country.trim().toUpperCase(),
  }
}

/** A fully built HTTP request that has NOT been sent. Contains the Authorization header: never log it. */
export interface PreparedRequest {
  readonly method: 'GET' | 'POST'
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
  readonly body?: string
}

export interface MapleradAdapterOptions {
  /** Which key slot is in use. Only 'sandbox' is permitted in Phase 0-3. */
  readonly environment: 'sandbox'
  /** Defaults to MAPLERAD_BASE_URL. Must be https. */
  readonly baseUrl?: string | undefined
  readonly secretKey?: Secret | undefined
  readonly webhookSecret?: Secret | undefined
  readonly allowedWebhookIps?: readonly string[] | undefined
}

export class MapleradAdapter implements ProviderAdapter {
  readonly name = 'maplerad' as const
  readonly environment: 'sandbox'
  readonly baseUrl: string
  readonly hasSecretKey: boolean
  /** Present only when a `whsec_` signing secret is configured. */
  readonly webhookVerifier: MapleradWebhookVerifier | undefined
  readonly #secretKey: Secret | undefined

  constructor(options: MapleradAdapterOptions) {
    this.environment = options.environment
    const baseUrl = (options.baseUrl ?? MAPLERAD_BASE_URL).replace(/\/+$/, '')
    if (!baseUrl.startsWith('https://')) {
      throw new MapleradInputError('Maplerad base URL must use https:// (VERIFIED: HTTPS only, never disable certificate verification)')
    }
    this.baseUrl = baseUrl
    this.#secretKey = options.secretKey
    this.hasSecretKey = options.secretKey !== undefined
    this.webhookVerifier = options.webhookSecret
      ? new MapleradWebhookVerifier({
          signingSecret: options.webhookSecret,
          allowedSourceIps: options.allowedWebhookIps ?? [],
        })
      : undefined
  }

  // ---------- Pure request builders (verified shapes, nothing is sent) ----------

  private authHeaders(): Readonly<Record<string, string>> {
    if (!this.#secretKey) {
      throw new MapleradInputError('Maplerad secret key not configured (MAPLERAD_SECRET_KEY_SANDBOX)')
    }
    return Object.freeze({
      Authorization: mapleradAuthorizationHeader(this.#secretKey),
      'Content-Type': 'application/json',
      Accept: 'application/json',
    })
  }

  /** Builds (does not send) the VERIFIED Tier 0 create-customer request. */
  prepareCreateCustomer(input: CustomerInput): PreparedRequest {
    const body = toMapleradCreateCustomerBody(input)
    return Object.freeze({
      method: 'POST',
      url: `${this.baseUrl}${MAPLERAD_PATHS.createCustomer}`,
      headers: this.authHeaders(),
      body: JSON.stringify(body),
    })
  }

  // ---------- ProviderAdapter — all UNVERIFIED / no live calls ----------

  async checkAuth(): Promise<void> {
    unverified(
      'Maplerad auth header format is verified, but no auth-check endpoint/response is confirmed and live calls are disabled in Phase 1',
    )
  }

  async createCustomer(input: CustomerInput): Promise<ProviderCustomer> {
    // Validate against the verified request shape first so bad input fails before anything else.
    toMapleradCreateCustomerBody(input)
    unverified('Maplerad create-customer response schema not confirmed — capture it from a real sandbox call (no live calls in Phase 1)')
  }

  async upgradeCustomerKyc(_input: KycUpgradeInput): Promise<ProviderCustomer> {
    unverified('Maplerad Upgrade Customer (Tier 1 / Tier 2) request and response fields not confirmed')
  }

  async createAccount(_input: AccountInput): Promise<ProviderAccount> {
    unverified('Maplerad virtual account / wallet creation and country coverage not confirmed')
  }

  async getBalances(_tenantId: TenantId): Promise<Balance[]> {
    unverified('Maplerad wallets endpoint shape (incl. USD SPEND/TREASURY split) not confirmed')
  }

  async quoteFx(_input: FxInput): Promise<FxQuote> {
    unverified('Maplerad FX quote endpoint not confirmed (known: quote then exchange by quote reference)')
  }

  async executeFx(_tenantId: TenantId, _quoteRef: string): Promise<FxResult> {
    unverified('Maplerad FX exchange endpoint not confirmed')
  }

  async createPayout(_input: PayoutInput, _idempotencyKey: string): Promise<PayoutResult> {
    unverified('Maplerad transfers endpoint, idempotency header and payout country coverage not confirmed')
  }

  async issueCard(_input: CardInput): Promise<Card> {
    unverified('Maplerad issuing endpoint and SPEND-wallet funding flow not confirmed')
  }

  /**
   * Signature verification is VERIFIED and enforced here. Event names and payload shapes are not,
   * so a correctly signed event still throws UnverifiedError until maplerad.dev/docs/overview-7 is read.
   */
  async parseWebhook(rawBody: string, headers: WebhookHeaders, context?: VerifyContext): Promise<ProviderEvent> {
    if (!this.webhookVerifier) {
      throw new MapleradInputError('Maplerad webhook signing secret not configured (MAPLERAD_WEBHOOK_SECRET)')
    }
    const result = this.webhookVerifier.verify(rawBody, headers, context)
    if (!result.ok) {
      throw new Error(`Maplerad webhook signature invalid: ${result.reason}`)
    }
    unverified('Maplerad webhook event names and payload shapes not confirmed (https://maplerad.dev/docs/overview-7)')
  }
}
