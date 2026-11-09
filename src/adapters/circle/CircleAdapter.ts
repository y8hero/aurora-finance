import { Secret } from '../../config/env'
import type { TenantId } from '../../core/types'
import type {
  AccountInput,
  Balance,
  ProviderAccount,
  ProviderAdapter,
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
import { responseShape, type ShapeNode } from '../../probes/shape'

export interface CircleAdapterOptions {
  readonly environment: 'testnet'
  readonly apiKey?: Secret | undefined
  readonly baseUrl?: string | undefined
  readonly transport?: HttpTransport | undefined
}

export interface CircleProbeResult {
  readonly host: string
  readonly path: string
  readonly status: number
  readonly shape: ShapeNode
}

const CIRCLE_DEFAULT_BASE_URL = 'https://api.circle.com'

export const CIRCLE_PATHS = Object.freeze({
  publicKey: '/v1/w3s/config/entity/publicKey',
  wallets: '/v1/w3s/wallets?pageSize=5',
  balances: '/v1/businessAccount/balances',
})

export class CircleAdapter implements ProviderAdapter {
  readonly name = 'circle' as const
  readonly environment = 'testnet' as const
  readonly hasApiKey: boolean
  readonly hasBaseUrl: boolean
  readonly baseUrl: string
  readonly #apiKey: Secret | undefined
  readonly #transport: HttpTransport

  constructor(options: CircleAdapterOptions) {
    this.#apiKey = options.apiKey
    this.hasApiKey = options.apiKey !== undefined
    this.baseUrl = (options.baseUrl ?? CIRCLE_DEFAULT_BASE_URL).replace(/\/+$/, '')
    this.hasBaseUrl = options.baseUrl !== undefined
    this.#transport = options.transport ?? new FetchHttpTransport()
  }

  private async get(path: string): Promise<GetResponse> {
    if (!this.#apiKey) {
      throw new Error(
        'Missing required environment variable: CIRCLE_API_KEY_TESTNET',
      )
    }

    const response = await this.#transport.get({
      url: `${this.baseUrl}${path}`,
      headers: bearerHeaders(this.#apiKey.reveal()),
    })

    assertNoRedirect(response.status)
    return response
  }

  async checkAuth(): Promise<void> {
    const response = await this.get(CIRCLE_PATHS.publicKey)

    if (response.status >= 400) {
      throw new Error(
        `Circle public-key probe returned HTTP ${response.status}`,
      )
    }
  }

  async probeWallets(): Promise<CircleProbeResult> {
    const response = await this.get(CIRCLE_PATHS.wallets)

    return {
      host: new URL(this.baseUrl).host,
      path: CIRCLE_PATHS.wallets,
      status: response.status,
      shape: responseShape(response.body),
    }
  }

  async probeMint(baseUrl: string): Promise<CircleProbeResult> {
    const client = new CircleAdapter({
      environment: 'testnet',
      apiKey: this.#apiKey,
      baseUrl,
      transport: this.#transport,
    })

    const response = await client.get(CIRCLE_PATHS.balances)

    return {
      host: new URL(baseUrl).host,
      path: CIRCLE_PATHS.balances,
      status: response.status,
      shape: responseShape(response.body),
    }
  }

  async createAccount(_input: AccountInput): Promise<ProviderAccount> {
    unverified('Circle wallet product and account permissions are not confirmed')
  }

  async getBalances(_tenantId: TenantId): Promise<Balance[]> {
    unverified('Circle balance response schema is not confirmed')
  }

  async parseWebhook(
    _rawBody: string,
    _headers: WebhookHeaders,
  ): Promise<ProviderEvent> {
    unverified('Circle webhook signature scheme is not confirmed')
  }

  resolveAssetAddress(_asset: 'USDC' | 'EURC', _chain: string): never {
    unverified('Circle contract address reference is not loaded')
  }
}
