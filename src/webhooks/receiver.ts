import { createHash } from 'node:crypto'
import type { WebhookHeaders } from '../adapters/types'
import { headerValue, type VerifyContext, type VerifierRegistry } from './signature'
import type { AuditLog } from '../core/audit/auditLog'
import type { ProviderName, TenantId } from '../core/types'
import type { Logger } from '../logging/logger'
import type { WebhookEventRecord, WebhookEventStore } from './eventStore'

export interface WebhookParser {
  readonly provider: ProviderName
  parse(rawBody: string): { eventId: string; eventType: string; occurredAt?: string }
}

export type ReceiveOutcome =
  | { readonly status: 'stored'; readonly record: WebhookEventRecord }
  | { readonly status: 'duplicate'; readonly record: WebhookEventRecord }
  | { readonly status: 'rejected'; readonly reason: string }

export interface ReceiveInput {
  readonly provider: ProviderName
  readonly tenantId: TenantId
  readonly rawBody: string
  readonly headers: WebhookHeaders
  readonly sourceIp?: string
}

export interface WebhookReceiverDeps {
  readonly verifiers: VerifierRegistry
  readonly parsers: ReadonlyMap<ProviderName, WebhookParser>
  readonly store: WebhookEventStore
  readonly audit: AuditLog
  readonly logger: Logger
  readonly now?: () => Date
}

export class WebhookReceiver {
  constructor(private readonly deps: WebhookReceiverDeps) {}

  async receive(input: ReceiveInput): Promise<ReceiveOutcome> {
    const now = (this.deps.now ?? (() => new Date()))()
    const verifier = this.deps.verifiers.get(input.provider)
    const parser = this.deps.parsers.get(input.provider)

    if (!verifier || !parser) {
      return this.reject(input.tenantId, input.provider, `no verifier/parser registered for provider ${input.provider}`)
    }

    const verification = verifier.verify(input.rawBody, input.headers, input.sourceIp ? { sourceIp: input.sourceIp } : {})
    if (!verification.ok) {
      return this.reject(input.tenantId, input.provider, verification.reason ?? 'signature verification failed')
    }

    let parsed: ReturnType<WebhookParser['parse']>
    try {
      parsed = parser.parse(input.rawBody)
    } catch (error) {
      return this.reject(input.tenantId, input.provider, `unparseable body: ${(error as Error).message}`)
    }

    /**
     * Maplerad delivery deduplication is based on svix-id, not the event
     * payload ID. The fallback keeps the mock provider compatible.
     */
    const deliveryId = headerValue(input.headers, 'svix-id') ?? parsed.eventId
    const record: WebhookEventRecord = {
      tenant_id: input.tenantId,
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
      this.deps.logger.info(
        { provider: input.provider, tenantId: input.tenantId, svixId: deliveryId },
        'webhook duplicate ignored',
      )
      await this.deps.audit.append({
        tenant_id: input.tenantId,
        actor: `webhook:${input.provider}`,
        action: 'webhook.duplicate_ignored',
        metadata: { svixId: deliveryId, eventId: parsed.eventId },
      })
      return { status: 'duplicate', record: result.record }
    }

    this.deps.logger.info(
      { provider: input.provider, tenantId: input.tenantId, svixId: deliveryId },
      'webhook stored',
    )
    await this.deps.audit.append({
      tenant_id: input.tenantId,
      actor: `webhook:${input.provider}`,
      action: 'webhook.stored',
      after: { svixId: deliveryId, eventId: parsed.eventId, eventType: parsed.eventType },
    })

    return { status: 'stored', record: result.record }
  }

  private async reject(tenantId: TenantId, provider: ProviderName, reason: string): Promise<ReceiveOutcome> {
    this.deps.logger.warn({ provider, tenantId, reason }, 'webhook rejected')
    await this.deps.audit.append({
      tenant_id: tenantId,
      actor: `webhook:${provider}`,
      action: 'webhook.rejected',
      metadata: { reason },
    })
    return { status: 'rejected', reason }
  }
}
