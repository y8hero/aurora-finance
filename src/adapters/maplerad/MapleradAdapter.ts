import { Secret } from '../../config/env'
import currencyData from '../../config/maplerad-currency-allowlist.json'
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
import {
  FetchHttpTransport,
  type GetResponse,
  type HttpTransport,
  assertNoRedirect,
  bearerHeaders,
} from '../../providers/http'
import { MapleradWebhookVerifier } from './MapleradWebhookVerifier'
import type { VerifyContext } from '../../webhooks/signature'

export const MAPLERAD_BASE_URL = 'https://api.maplerad.com'
export const MAPLERAD_DASHBOARD_URL = 'https://app.maplerad.com'

export const MAPLERAD_PATHS = Object.freeze({
  createCustomer: '/v1/customers',
  countries: '/v1/countries',
  currencies: '/v1/currencies',
  institutions: '/v1/institutions?country=NG&type=VIRTUAL',
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
export type MapleradUsdWalletKind = 'SPEND' | 'TREASURY'

export const MAPLERAD_OBSERVED_CURRENCY_CODES: readonly string[] = Object.freeze(
  currencyData.codes.map((code) => code.toUpperCase()),
)

const mapleradObservedCurrencies = new Set(MAPLERAD_OBSERVED_CURRENCY_CODES)

export class MapleradUnsupportedCurrencyError extends Error {
  override name = 'MapleradUnsupportedCurrencyError'

  constructor(readonly currency: string) {
    super(
      `Currency or asset ${currency.toUpperCase()} is not in the unverified Maplerad sandbox allow-list`,
    )
  }
}

export function assertMapleradObservedCurrency(currency: string): void {
  const normalized = currency.trim().toUpperCase()

  if (!mapleradObservedCurrencies.has(normalized)) {
    throw new MapleradUnsupportedCurrencyError(currency)
  }
}

export function mapleradAuthorizationHeader(secret: Secret): string {
  return `Bearer ${secret.reveal()}`
}

export interface MapleradCreateCustomerBody {
  readonly first_name: string
  readonly last_name: string
  readonly email: string
  readonly country: string
}

export class MapleradInputError extends Error {
  override name = 'MapleradInputError'
}

export function toMapleradCreateCustomerBody(
  input: CustomerInput,
): MapleradCreateCustomerBody {
  const fields = {
    first_name: input.firstName,
    last_name: input.lastName,
    email: input.email,
    country: input.country,
  }

  for (const [field, value] of Object.entries(fields)) {
    if (!value.trim()) {
      throw new MapleradInputError(
        `Maplerad create-customer requires non-empty "${field}"`,
      )
    }
  }

  return {
    first_name: input.firstName.trim(),
    last_name: input.lastName.trim(),
    email: input.email.trim(),
    country: input.country.trim().toUpperCase(),
  }
}

export interface PreparedRequest {
  readonly method: 'GET' | 'POST'
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
  readonly body?: string
}

export interface MapleradAdapterOptions {
  readonly environment: 'sandbox'
  readonly baseUrl?: string | undefined
  readonly secretKey?: Secret | undefined
  readonly webhookSecret?: Secret | undefined
  readonly allowedWebhookIps?: readonly string[] | undefined
  readonly transport?: HttpTransport | undefined
}

export class MapleradAdapter implements ProviderAdapter {
  readonly name = 'maplerad' as const
  readonly environment = 'sandbox' as const
  readonly baseUrl: string
  readonly hasSecretKey: boolean
  readonly webhookVerifier: MapleradWebhookVerifier | undefined
  readonly #secretKey: Secret | undefined
  readonly #transport: HttpTransport
  #lastCheckAuthResponse: GetResponse | undefined

  constructor(options: MapleradAdapterOptions) {
    this.baseUrl = (options.baseUrl ?? MAPLERAD_BASE_URL).replace(/\/+$/, '')

    if (!this.baseUrl.startsWith('https://')) {
      throw new MapleradInputError('Maplerad base URL must use https://')
    }

    this.#secretKey = options.secretKey
    this.hasSecretKey = options.secretKey !== undefined
    this.#transport = options.transport ?? new FetchHttpTransport()

    this.webhookVerifier = options.webhookSecret
      ? new MapleradWebhookVerifier({
          signingSecret: options.webhookSecret,
          allowedSourceIps: options.allowedWebhookIps ?? [],
        })
      : undefined
  }

  get lastCheckAuthResponse(): GetResponse | undefined {
    return this.#lastCheckAuthResponse
  }

  private authHeaders(): Readonly<Record<string, string>> {
    if (!this.#secretKey) {
      throw new MapleradInputError(
        'Missing required environment variable: MAPLERAD_SECRET_KEY_SANDBOX',
      )
    }

    return bearerHeaders(this.#secretKey.reveal())
  }

  private async get(path: string): Promise<GetResponse> {
    const response = await this.#transport.get({
      url: `${this.baseUrl}${path}`,
      headers: this.authHeaders(),
    })

    assertNoRedirect(response.status)
    return response
  }

  async checkAuth(): Promise<void> {
    this.#lastCheckAuthResponse = await this.get(MAPLERAD_PATHS.countries)

    if (this.#lastCheckAuthResponse.status >= 400) {
      throw new Error(
        `Maplerad countries probe returned HTTP ${this.#lastCheckAuthResponse.status}`,
      )
    }
  }

  async probeCountries(): Promise<GetResponse> {
    return this.get(MAPLERAD_PATHS.countries)
  }

  async probeCurrencies(): Promise<GetResponse> {
    return this.get(MAPLERAD_PATHS.currencies)
  }

  async probeInstitutions(): Promise<GetResponse> {
    return this.get(MAPLERAD_PATHS.institutions)
  }

  prepareCreateCustomer(input: CustomerInput): PreparedRequest {
    const body = toMapleradCreateCustomerBody(input)

    return {
      method: 'POST',
      url: `${this.baseUrl}${MAPLERAD_PATHS.createCustomer}`,
      headers: {
        ...this.authHeaders(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    }
  }

  async createCustomer(input: CustomerInput): Promise<ProviderCustomer> {
    toMapleradCreateCustomerBody(input)
    unverified('Maplerad create-customer response schema not confirmed')
  }

  async upgradeCustomerKyc(
    _input: KycUpgradeInput,
  ): Promise<ProviderCustomer> {
    unverified('Maplerad customer upgrade response schema not confirmed')
  }

  async createAccount(input: AccountInput): Promise<ProviderAccount> {
    assertMapleradObservedCurrency(input.currency)
    unverified('Maplerad account response schema not confirmed')
  }

  async getBalances(_tenantId: TenantId): Promise<Balance[]> {
    unverified('Maplerad balance response schema not confirmed')
  }

  async quoteFx(input: FxInput): Promise<FxQuote> {
    assertMapleradObservedCurrency(input.sell.currency)
    assertMapleradObservedCurrency(input.buyCurrency)
    unverified('Maplerad FX response schema not confirmed')
  }

  async executeFx(
    _tenantId: TenantId,
    _quoteRef: string,
  ): Promise<FxResult> {
    unverified('Maplerad FX exchange response schema not confirmed')
  }

  async createPayout(
    input: PayoutInput,
    _idempotencyKey: string,
  ): Promise<PayoutResult> {
    assertMapleradObservedCurrency(input.amount.currency)
    unverified('Maplerad payout response schema not confirmed')
  }

  async issueCard(input: CardInput): Promise<Card> {
    assertMapleradObservedCurrency(input.currency)
    unverified('Maplerad issuing response schema not confirmed')
  }

  async parseWebhook(
    rawBody: string,
    headers: WebhookHeaders,
    context?: VerifyContext,
  ): Promise<ProviderEvent> {
    if (!this.webhookVerifier) {
      throw new MapleradInputError(
        'Missing required environment variable: MAPLERAD_WEBHOOK_SECRET',
      )
    }

    const result = this.webhookVerifier.verify(rawBody, headers, context)

    if (!result.ok) {
      throw new Error(`Maplerad webhook signature invalid: ${result.reason}`)
    }

    unverified('Maplerad webhook event names and payload shapes not confirmed')
  }
}
