import type {
  ISODateTime,
  ProviderName,
  TenantId,
  TenantRecord,
} from '../core/types'

export interface WebhookEventRecord extends TenantRecord {
  readonly provider: ProviderName
  readonly svix_id: string
  readonly event_id: string
  readonly event_type: string
  readonly signature_ok: true
  readonly raw_body_hash: string
  readonly raw_body: string
  readonly received_at: ISODateTime
  readonly processed_at?: ISODateTime
}

export interface InsertResult {
  readonly inserted: boolean
  readonly record: WebhookEventRecord
}

export interface WebhookEventStore {
  insertIfAbsent(record: WebhookEventRecord): Promise<InsertResult>
  findByDelivery(
    provider: ProviderName,
    deliveryId: string,
  ): Promise<WebhookEventRecord | undefined>
  markProcessed(
    tenantId: TenantId,
    provider: ProviderName,
    deliveryId: string,
    at: ISODateTime,
  ): Promise<void>
  list(tenantId: TenantId): Promise<readonly WebhookEventRecord[]>
}

export class InMemoryWebhookEventStore implements WebhookEventStore {
  private readonly byKey = new Map<string, WebhookEventRecord>()

  private key(provider: ProviderName, deliveryId: string): string {
    return `${provider}::${deliveryId}`
  }

  async insertIfAbsent(record: WebhookEventRecord): Promise<InsertResult> {
    const key = this.key(record.provider, record.svix_id)
    const existing = this.byKey.get(key)

    if (existing) {
      return { inserted: false, record: existing }
    }

    const frozen = Object.freeze({ ...record })
    this.byKey.set(key, frozen)
    return { inserted: true, record: frozen }
  }

  async findByDelivery(
    provider: ProviderName,
    deliveryId: string,
  ): Promise<WebhookEventRecord | undefined> {
    return this.byKey.get(this.key(provider, deliveryId))
  }

  async markProcessed(
    tenantId: TenantId,
    provider: ProviderName,
    deliveryId: string,
    at: ISODateTime,
  ): Promise<void> {
    const key = this.key(provider, deliveryId)
    const existing = this.byKey.get(key)

    if (!existing || existing.tenant_id !== tenantId) {
      throw new Error(`Webhook delivery not found for tenant ${tenantId}`)
    }

    this.byKey.set(
      key,
      Object.freeze({ ...existing, processed_at: at }),
    )
  }

  async list(tenantId: TenantId): Promise<readonly WebhookEventRecord[]> {
    return Object.freeze(
      [...this.byKey.values()].filter(
        (record) => record.tenant_id === tenantId,
      ),
    )
  }
}
