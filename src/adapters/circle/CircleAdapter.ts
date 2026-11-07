import type { Secret } from '../../config/env'
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

/**
 * VERIFIED (from developers.circle.com):
 *  - Auth is a Bearer API key.
 *  - Testnet and mainnet use SEPARATE keys and may use different base URLs.
 *  - CCTP V2 for cross-chain USDC/EURC.
 *  - Never hardcode USDC/EURC contract addresses; resolve from Circle's address reference / MCP.
 *  - Official skills: github.com/circlefin/skills.
 *
 * UNVERIFIED (blocking): which Circle wallet product this account uses. If it is
 * developer-controlled wallets, Aurora would hold keys, contradicting the no-custody model.
 * No wallet feature may be built until that is answered. Also unverified: base URLs,
 * Solana support per asset (USDC, EURC, USDT, PYUSD), third-party-tenant permission.
 *
 * Aurora never holds keys, entity secrets or recovery files in code or config here.
 */
export type CircleEnvironment = 'testnet' | 'mainnet'

export interface CircleAdapterOptions {
  readonly environment: 'testnet'
  readonly apiKey?: Secret | undefined
  /** UNVERIFIED until confirmed via Circle MCP / docs. */
  readonly baseUrl?: string | undefined
}

export class CircleAdapter implements ProviderAdapter {
  readonly name = 'circle' as const
  readonly environment: 'testnet'
  readonly hasApiKey: boolean
  readonly hasBaseUrl: boolean

  constructor(options: CircleAdapterOptions) {
    this.environment = options.environment
    this.hasApiKey = options.apiKey !== undefined
    this.hasBaseUrl = options.baseUrl !== undefined
    // Secret is deliberately not retained: nothing in this stub may use it.
  }

  async checkAuth(): Promise<void> {
    unverified('Circle testnet base URL and account product not confirmed via Circle MCP')
  }

  async createAccount(_input: AccountInput): Promise<ProviderAccount> {
    unverified('Circle wallet product (custodied vs developer-controlled) not confirmed — no wallet feature may be built')
  }

  async getBalances(_tenantId: TenantId): Promise<Balance[]> {
    unverified('Circle balance endpoint for our account product not confirmed')
  }

  async parseWebhook(_rawBody: string, _headers: WebhookHeaders): Promise<ProviderEvent> {
    unverified('Circle webhook notification signature scheme not confirmed')
  }

  /** Contract addresses are never hardcoded (brief §4). Must come from Circle's address reference. */
  resolveAssetAddress(_asset: 'USDC' | 'EURC', _chain: string): never {
    unverified('Circle contract address reference not loaded; never hardcode addresses')
  }
}
