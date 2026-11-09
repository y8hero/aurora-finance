import { createHash } from 'node:crypto'
import type { WebhookHeaders } from '../adapters/types'
import type { AuditLog } from '../core/audit/auditLog'
import { PLATFORM_TENANT, type ProviderName, type TenantId } from '../core/types'
import type { Logger } from '../logging/logger'
import type { WebhookEventRecord, WebhookEventStore } from './eventStore'
import { headerValue, type VerifierRegistry } from './signature'

export interface WebhookParser {
  readonly provider: ProviderName
  parse(rawBody: string): {
    eventId: string
    eventType: string
    occurredAt?: string
    providerCustomerId?: string
  }
}

export interface WebhookTenantResolver {
  resolve(provider: ProviderName, providerCustomerId: string): Promise<TenantId | undefined>
}

export type ReceiveOutcome =
  | { readonly status: 'stored'; readonly record: WebhookEventRecord }
  | { readonly status: 'duplicate'; readonly record: WebhookEventRecord }
  | { readonly status: 'rejected'; readonly reason: string }

export interface ReceiveInput {
  readonly provider: ProviderName
  readonly rawBody: string
  readonly headers: WebhookHeaders
  readonly sourceIp?: string
}

export interface WebhookReceiverDeps {
  readonly verifiers: VerifierRegistry
  readonly parsers: ReadonlyMap<ProviderName, WebhookParser>
  readonly tenantResolver: WebhookTenantResolver
  readonly store: WebhookEventStore
  readonly audit: AuditLog
  readonly logger: Logger
  readonly now?: () => Date
}

export class WebhookReceiver {
  constructor(private readonly deps: WebhookReceiverDeps) {}

  async receive(input: ReceiveInput): Promise<ReceiveOutcome> {
    const verifier = this.deps.verifiers.get(input.provider)
    const parser = this.deps.parsers.get(input.provider)

    if (!verifier || !parser) {
      return this.reject(input.provider, 'no verifier/parser registered')
    }

    const verification = verifier.verify(
      input.rawBody,
      input.headers,
      input.sourceIp ? { sourceIp: input.sourceIp } : {},
    )

    if (!verification.ok) {
      return this.reject(input.provider, verification.reason ?? 'signature verification failed')
    }

    let parsed: ReturnType<WebhookParser['parse']>
    try {
      parsed = parser.parse(input.rawBody)
    } catch (error) {
      return this.reject(input.provider, `unparseable body: ${(error as Error).message}`)
    }

    if (!parsed.providerCustomerId) {
      return this.reject(input.provider, 'verified payload has no provider customer ID')
    }

    const resolvedTenant = await this.deps.tenantResolver.resolve(
      input.provider,
      parsed.providerCustomerId,
    )

    if (!resolvedTenant) {
      return this.reject(input.provider, 'provider customer is not mapped to a tenant')
    }

    const deliveryId = headerValue(input.headers, 'svix-id') ?? parsed.eventId
    const now = (this.deps.now ?? (() => new Date()))()
    const record: WebhookEventRecord = {
      tenant_id: resolvedTenant,
      provider: input.provider,
      svix_id: deliveryId,
      event_id: parsed.eventId,
      event_type: parsed.eventType,
      signature_ok: true,
      raw_body_hash: createHash('sha256').update(input.rawBody).digest('hex'),
      raw_body: input.rawBody,
      received_at: now.toISOString(),
    }

    const result = await this.deps.store.insertIfAbsent(record)

    if (!result.inserted) {
      if (result.record.tenant_id !== resolvedTenant) {
        return this.reject(
          input.provider,
          'delivery replayed for a different tenant',
        )
      }

      this.deps.logger.info(
        { provider: input.provider, tenantId: resolvedTenant, svixId: deliveryId },
        'webhook duplicate ignored',
      )

      await this.deps.audit.append({
        tenant_id: resolvedTenant,
        actor: `webhook:${input.provider}`,
        action: 'webhook.duplicate_ignored',
        metadata: { svixId: deliveryId, eventId: parsed.eventId },
      })

      return { status: 'duplicate', record: result.record }
    }

    await this.deps.audit.append({
      tenant_id: resolvedTenant,
      actor: `webhook:${input.provider}`,
      action: 'webhook.stored',
      after: { svixId: deliveryId, eventId: parsed.eventId },
    })

    return { status: 'stored', record: result.record }
  }

  private async reject(provider: ProviderName, reason: string): Promise<ReceiveOutcome> {
    this.deps.logger.warn({ provider, reason }, 'webhook rejected')

    await this.deps.audit.append({
      tenant_id: PLATFORM_TENANT,
      actor: `webhook:${provider}`,
      action: 'webhook.rejected',
      metadata: { reason },
    })

    return { status: 'rejected', reason }
  }
}
