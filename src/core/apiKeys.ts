import { createHash, randomBytes, timingSafeEqual, randomUUID } from 'node:crypto'
import type { TenantId } from './types'

export type ApiKeyScope = 'read' | 'write'
export type ApiKeyStatus = 'active' | 'revoked'

export interface ApiKeyRecord {
  readonly id: string
  readonly tenant_id: TenantId
  readonly key_prefix: string
  readonly scopes: readonly ApiKeyScope[]
  readonly status: ApiKeyStatus
  readonly created_at: string
  readonly last_used_at?: string
}

export interface ApiKeyCreationResult extends Omit<ApiKeyRecord, 'last_used_at'> {
  readonly key: string
}

export interface ApiKeyRepository {
  create(input: {
    readonly id: string
    readonly tenant_id: TenantId
    readonly key_prefix: string
    readonly key_hash: string
    readonly scopes: readonly ApiKeyScope[]
  }): Promise<ApiKeyRecord>
  findActiveByKeyHash(keyHash: string): Promise<ApiKeyRecord | undefined>
  listByTenant(tenantId: TenantId): Promise<readonly ApiKeyRecord[]>
  revoke(tenantId: TenantId, id: string): Promise<void>
  touchLastUsed(id: string): Promise<void>
}

export class ApiKeyTenantError extends Error {
  override name = 'ApiKeyTenantError'
}

export class ApiKeyInvalidError extends Error {
  override name = 'ApiKeyInvalidError'
}

export class ApiKeyScopeError extends Error {
  override name = 'ApiKeyScopeError'
}

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key, 'utf8').digest('hex')
}

export function generateApiKey(): { key: string; prefix: string } {
  const secret = randomBytes(32).toString('base64url')
  const prefix = randomBytes(4).toString('hex')
  return { key: `aur_${prefix}_${secret}`, prefix }
}

function equalHashes(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8')
  const b = Buffer.from(right, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}

export class ApiKeyService {
  constructor(
    private readonly repository: ApiKeyRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async create(
    tenant_id: TenantId,
    scopes: readonly ApiKeyScope[],
  ): Promise<ApiKeyCreationResult> {
    if (tenant_id === ('00000000-0000-0000-0000-000000000001' as TenantId)) {
      throw new ApiKeyTenantError('The platform tenant cannot receive tenant API keys')
    }

    const normalized = [...new Set(scopes)]
    if (
      normalized.length === 0 ||
      normalized.some((scope) => scope !== 'read' && scope !== 'write')
    ) {
      throw new ApiKeyScopeError('API key scopes must contain read and/or write')
    }

    const generated = generateApiKey()
    const record = await this.repository.create({
      id: randomUUID(),
      tenant_id,
      key_prefix: generated.prefix,
      key_hash: hashApiKey(generated.key),
      scopes: normalized,
    })

    return { ...record, key: generated.key }
  }

  async authenticate(
    presentedKey: string,
    requiredScope: ApiKeyScope,
  ): Promise<ApiKeyRecord> {
    const record = await this.repository.findActiveByKeyHash(hashApiKey(presentedKey))

    if (!record || record.status !== 'active') {
      throw new ApiKeyInvalidError('Invalid or revoked API key')
    }

    if (!record.scopes.includes(requiredScope)) {
      throw new ApiKeyScopeError(`API key lacks ${requiredScope} scope`)
    }

    const lastUsed = record.last_used_at ? Date.parse(record.last_used_at) : 0
    if (this.now().getTime() - lastUsed >= 60_000) {
      await this.repository.touchLastUsed(record.id)
    }

    return record
  }

  static equalSecrets(left: string, right: string): boolean {
    const a = createHash('sha256').update(left).digest()
    const b = createHash('sha256').update(right).digest()
    return a.length === b.length && timingSafeEqual(a, b)
  }
}
