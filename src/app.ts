import Fastify, {
  type FastifyInstance,
  type FastifyRequest,
  type FastifyReply,
} from 'fastify'
import { createHash } from 'node:crypto'
import { z } from 'zod'
import type { AppConfig, Secret } from './config/env'
import type { Logger } from './logging/logger'
import type { AuditLog } from './core/audit/auditLog'
import type { CustomerRepository } from './core/customers'
import {
  CustomerConflictError,
  ValidationError,
  type CustomerCreateInput,
} from './core/customers'
import {
  ApiKeyInvalidError,
  ApiKeyScopeError,
  ApiKeyService,
  type ApiKeyRecord,
} from './core/apiKeys'
import type { TenantRepository } from './core/tenants'
import type { WebhookReceiver } from './webhooks/receiver'
import type { IdempotencyStore } from './core/idempotency'
import { IdempotencyConflictError } from './core/idempotency'
import { TokenBucketRateLimiter } from './core/rateLimiter'
import { requestId } from './core/requestId'
import {
  PLATFORM_TENANT,
  tenantId,
  type TenantId,
  type ProviderName,
} from './core/types'
import { assertTenantJurisdictionAllowed } from './compliance/restrictedJurisdictions'

export class PayloadTooLargeError extends Error {
  override name = 'PayloadTooLargeError'
}

export interface AppDeps {
  readonly config: AppConfig
  readonly logger: Logger
  readonly audit: AuditLog
  readonly tenants: TenantRepository
  readonly apiKeyService: ApiKeyService
  readonly apiKeys: import('./core/apiKeys').ApiKeyRepository
  readonly customers: CustomerRepository
  readonly receiver: WebhookReceiver
  readonly idempotency: IdempotencyStore
  readonly tenantLimiter: TokenBucketRateLimiter
  readonly ipLimiter: TokenBucketRateLimiter
  readonly adminKey?: Secret
  readonly now?: () => Date
}

const MAX_BODY_BYTES = 1_000_000

export const OPENAPI_ROUTE_PATHS = [
  '/health',
  '/webhooks/:provider',
  '/v1/admin/tenants',
  '/v1/admin/tenants/:id',
  '/v1/admin/tenants/:id/api-keys',
  '/v1/admin/tenants/:id/api-keys/:keyId',
  '/v1/customers',
  '/v1/customers/:id',
  '/v1/audit',
  '/v1/audit/verify',
  '/v1/accounts',
  '/v1/accounts/:id/balances',
  '/v1/payouts',
  '/v1/fx/quotes',
  '/v1/cards',
] as const

interface RequestContext {
  tenantId?: TenantId
  apiKeyId?: string
}

interface NormalizedError {
  readonly message?: string
  readonly code?: string
  readonly statusCode?: number
}

function normalizedError(error: unknown): NormalizedError {
  if (error instanceof Error) {
    const candidate = error as Error & {
      code?: unknown
      statusCode?: unknown
    }

    return {
      message: candidate.message,
      ...(typeof candidate.code === 'string' ? { code: candidate.code } : {}),
      ...(typeof candidate.statusCode === 'number'
        ? { statusCode: candidate.statusCode }
        : {}),
    }
  }

  if (error && typeof error === 'object') {
    const candidate = error as {
      message?: unknown
      code?: unknown
      statusCode?: unknown
    }

    return {
      ...(typeof candidate.message === 'string'
        ? { message: candidate.message }
        : {}),
      ...(typeof candidate.code === 'string' ? { code: candidate.code } : {}),
      ...(typeof candidate.statusCode === 'number'
        ? { statusCode: candidate.statusCode }
        : {}),
    }
  }

  return {}
}

function errorResponse(
  reply: FastifyReply,
  status: number,
  code: string,
  message: string,
): FastifyReply {
  return reply.code(status).send({
    error: { code, message, requestId: reply.request.id },
  })
}

function bodyOf(request: FastifyRequest): unknown {
  if (typeof request.body === 'string') {
    try {
      return JSON.parse(request.body) as unknown
    } catch {
      return undefined
    }
  }

  return request.body
}

function bearer(request: FastifyRequest): string | undefined {
  const value = request.headers.authorization
  return value?.startsWith('Bearer ') ? value.slice(7) : undefined
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value
}

function requestContext(request: FastifyRequest): RequestContext {
  return request as FastifyRequest & RequestContext
}

function matchesAdmin(presented: string, configured: Secret): boolean {
  return ApiKeyService.equalSecrets(presented, configured.reveal())
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const app = Fastify({
    bodyLimit: MAX_BODY_BYTES,
    logger: false,
    genReqId: (request) => {
      const candidate = firstHeader(request.headers['x-request-id'])
      return requestId(candidate)
    },
  })

  app.addContentTypeParser(
    'application/json',
    { parseAs: 'string' },
    (_request, body, done) => {
      done(null, body)
    },
  )

  app.addHook('onRequest', async (request, reply) => {
    reply.header('x-request-id', request.id)

    const result = deps.ipLimiter.consume(request.ip)
    if (!result.allowed) {
      reply.header('retry-after', String(result.retryAfterSeconds))
      return errorResponse(reply, 429, 'rate_limited', 'rate limit exceeded')
    }
  })

  app.addHook('onResponse', async (request) => {
    deps.logger.info(
      { requestId: request.id, method: request.method, url: request.url },
      'request completed',
    )
  })

  app.setErrorHandler((error: unknown, request, reply) => {
    const details = normalizedError(error)

    if (
      error instanceof PayloadTooLargeError ||
      details.code === 'FST_ERR_CTP_BODY_TOO_LARGE'
    ) {
      return errorResponse(reply, 413, 'request_too_large', 'request too large')
    }

    if (details.statusCode === 400) {
      return errorResponse(reply, 400, 'validation_error', 'invalid request')
    }

    deps.logger.error(
      { requestId: request.id, message: details.message ?? 'request failed' },
      'request failed',
    )
    return errorResponse(reply, 500, 'internal_error', 'internal server error')
  })

  const requireAdmin = async (
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> => {
    if (!deps.adminKey) {
      errorResponse(reply, 404, 'not_found', 'not found')
      return
    }

    const presented = bearer(request)
    if (!presented || !matchesAdmin(presented, deps.adminKey)) {
      errorResponse(reply, 401, 'invalid_key', 'invalid API key')
    }
  }

  const requireTenant =
    (scope: 'read' | 'write') =>
    async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const presented = bearer(request)
      if (!presented) {
        errorResponse(reply, 401, 'invalid_key', 'invalid API key')
        return
      }

      let key: ApiKeyRecord
      try {
        key = await deps.apiKeyService.authenticate(presented, scope)
      } catch (error) {
        if (error instanceof ApiKeyScopeError) {
          errorResponse(reply, 403, 'insufficient_scope', 'insufficient scope')
        } else if (error instanceof ApiKeyInvalidError) {
          errorResponse(reply, 401, 'invalid_key', 'invalid API key')
        } else {
          errorResponse(reply, 401, 'invalid_key', 'invalid API key')
        }
        return
      }

      const limit = deps.tenantLimiter.consume(key.tenant_id)
      if (!limit.allowed) {
        reply.header('retry-after', String(limit.retryAfterSeconds))
        errorResponse(reply, 429, 'rate_limited', 'rate limit exceeded')
        return
      }

      const context = requestContext(request)
      context.tenantId = key.tenant_id
      context.apiKeyId = key.id
    }

  const auditMutation = async (
    request: FastifyRequest,
    action: string,
    after?: unknown,
  ): Promise<void> => {
    const context = requestContext(request)
    await deps.audit.append({
      tenant_id: context.tenantId ?? PLATFORM_TENANT,
      actor: context.apiKeyId ?? 'admin',
      action,
      ...(after === undefined ? {} : { after }),
    })
  }

  app.get('/health', async () => ({
    ok: true,
    phase: 2,
    env: deps.config.AURORA_ENV,
    database: deps.config.DATABASE_URL ? 'configured' : 'not configured',
    adapters: {
      mock: 'active',
      maplerad: 'stub',
      circle: 'stub',
    },
  }))

  app.post('/webhooks/:provider', async (request, reply) => {
    const provider = (request.params as { provider?: string }).provider

    if (!provider || !['maplerad', 'circle', 'mock'].includes(provider)) {
      return errorResponse(reply, 404, 'not_found', 'not found')
    }

    if (provider !== 'mock') {
      return errorResponse(
        reply,
        501,
        'provider_unverified',
        'provider webhook unavailable',
      )
    }

    const body =
      typeof request.body === 'string'
        ? request.body
        : JSON.stringify(request.body ?? {})

    const outcome = await deps.receiver.receive({
      provider: provider as ProviderName,
      rawBody: body,
      headers: Object.fromEntries(
        Object.entries(request.headers).map(([key, value]) => [
          key.toLowerCase(),
          value,
        ]),
      ),
      ...(request.ip ? { sourceIp: request.ip } : {}),
    })

    if (outcome.status === 'rejected') {
      return errorResponse(reply, 401, 'unauthorized', 'unauthorized')
    }

    return reply.code(200).send({
      status: outcome.status,
      svixId: outcome.record.svix_id,
      eventId: outcome.record.event_id,
      tenantId: outcome.record.tenant_id,
    })
  })

  app.post(
    '/v1/admin/tenants',
    { preHandler: requireAdmin },
    async (request, reply) => {
      const schema = z.object({
        slug: z.string().min(1).max(128),
        name: z.string().min(1).max(256),
        country: z.string().length(2),
      })
      const parsed = schema.safeParse(bodyOf(request))

      if (!parsed.success) {
        return errorResponse(reply, 400, 'validation_error', 'invalid tenant')
      }

      try {
        const tenant = await deps.tenants.create(parsed.data)
        await auditMutation(request, 'tenant.created', { id: tenant.id })
        return reply.code(201).send(tenant)
      } catch {
        return errorResponse(reply, 409, 'conflict', 'tenant already exists')
      }
    },
  )

  app.get('/v1/admin/tenants', { preHandler: requireAdmin }, async () =>
    deps.tenants.list(),
  )

  app.get(
    '/v1/admin/tenants/:id',
    { preHandler: requireAdmin },
    async (request, reply) => {
      try {
        const tenant = await deps.tenants.get(
          tenantId((request.params as { id: string }).id),
        )
        return tenant
          ? reply.send(tenant)
          : errorResponse(reply, 404, 'not_found', 'not found')
      } catch {
        return errorResponse(reply, 400, 'validation_error', 'invalid tenant id')
      }
    },
  )

  app.post(
    '/v1/admin/tenants/:id/api-keys',
    { preHandler: requireAdmin },
    async (request, reply) => {
      try {
        const target = tenantId((request.params as { id: string }).id)
        const parsed = z
          .object({
            scopes: z.array(z.enum(['read', 'write'])).min(1).max(2).default(['read']),
          })
          .safeParse(bodyOf(request))

        if (!parsed.success) {
          return errorResponse(reply, 400, 'validation_error', 'invalid scopes')
        }

        const result = await deps.apiKeyService.create(target, parsed.data.scopes)
        await auditMutation(request, 'api_key.created', {
          id: result.id,
          tenant_id: target,
          scopes: result.scopes,
        })
        return reply.code(201).send(result)
      } catch (error) {
        return error instanceof Error && error.message.includes('platform')
          ? errorResponse(reply, 403, 'forbidden', 'forbidden')
          : errorResponse(reply, 404, 'not_found', 'tenant not found')
      }
    },
  )

  app.get(
    '/v1/admin/tenants/:id/api-keys',
    { preHandler: requireAdmin },
    async (request, reply) => {
      try {
        const target = tenantId((request.params as { id: string }).id)
        return reply.send(await deps.apiKeys.listByTenant(target))
      } catch {
        return errorResponse(reply, 403, 'forbidden', 'forbidden')
      }
    },
  )

  app.delete(
    '/v1/admin/tenants/:id/api-keys/:keyId',
    { preHandler: requireAdmin },
    async (request, reply) => {
      try {
        const target = tenantId((request.params as { id: string }).id)
        await deps.apiKeys.revoke(
          target,
          (request.params as { keyId: string }).keyId,
        )
        await auditMutation(request, 'api_key.revoked', { tenant_id: target })
        return reply.code(204).send()
      } catch {
        return errorResponse(reply, 404, 'not_found', 'API key not found')
      }
    },
  )

  app.post(
    '/v1/customers',
    { preHandler: requireTenant('write') },
    async (request, reply) => {
      const schema = z.object({
        external_ref: z.string().max(256).optional(),
        first_name: z.string().min(1).max(128),
        last_name: z.string().min(1).max(128),
        email: z.string().email().max(320),
        country: z.string().length(2),
        beneficialOwners: z
          .array(
            z.object({
              name: z.string().max(256),
              country: z.string().optional(),
              address: z.string().max(512).optional(),
            }),
          )
          .max(32)
          .optional(),
      })

      const parsed = schema.safeParse(bodyOf(request))
      if (!parsed.success) {
        return errorResponse(reply, 400, 'validation_error', 'invalid customer')
      }

      const beneficialOwners = (parsed.data.beneficialOwners ?? []).map((owner) => ({
        name: owner.name,
        ...(typeof owner.country === 'string'
          ? { country: owner.country }
          : {}),
        ...(typeof owner.address === 'string'
          ? { address: owner.address }
          : {}),
      }))

      const tenant = requestContext(request).tenantId!
      try {
        assertTenantJurisdictionAllowed({
          country: parsed.data.country,
          beneficialOwners,
        })
      } catch {
        return errorResponse(
          reply,
          422,
          'jurisdiction_review_required',
          'jurisdiction review required',
        )
      }

      const input: CustomerCreateInput = {
        ...(parsed.data.external_ref === undefined
          ? {}
          : { external_ref: parsed.data.external_ref }),
        first_name: parsed.data.first_name,
        last_name: parsed.data.last_name,
        email: parsed.data.email,
        country: parsed.data.country,
        kyc_tier: 0,
        status: 'active',
      }

      const idempotencyHeader = firstHeader(request.headers['idempotency-key'])
      if (!idempotencyHeader || idempotencyHeader.trim().length === 0) {
        return errorResponse(
          reply,
          400,
          'validation_error',
          'Idempotency-Key header is required',
        )
      }

      const fingerprint = createHash('sha256')
        .update(JSON.stringify(parsed.data))
        .digest('hex')

      try {
        const customer = await deps.idempotency.run(
          tenant,
          idempotencyHeader,
          fingerprint,
          () => deps.customers.create(tenant, input),
        )
        await auditMutation(request, 'customer.created', { id: customer.id })
        return reply.code(201).send(customer)
      } catch (error) {
        if (error instanceof IdempotencyConflictError) {
          const mismatch = error.message.includes('different')
          return errorResponse(
            reply,
            mismatch ? 422 : 409,
            mismatch ? 'idempotency_mismatch' : 'idempotency_in_progress',
            mismatch
              ? 'idempotency key payload mismatch'
              : 'request already in progress',
          )
        }

        if (error instanceof CustomerConflictError) {
          return errorResponse(reply, 409, 'conflict', 'customer already exists')
        }

        return errorResponse(reply, 500, 'internal_error', 'internal server error')
      }
    },
  )

  app.get(
    '/v1/customers',
    { preHandler: requireTenant('read') },
    async (request, reply) => {
      const query = request.query as { limit?: string; cursor?: string }
      const limit = query.limit === undefined ? 50 : Number(query.limit)

      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return errorResponse(reply, 400, 'validation_error', 'invalid limit')
      }

      try {
        return reply.send(
          await deps.customers.list(
            requestContext(request).tenantId!,
            limit,
            query.cursor,
          ),
        )
      } catch (error) {
        return error instanceof ValidationError
          ? errorResponse(reply, 400, 'validation_error', 'invalid cursor')
          : errorResponse(reply, 500, 'internal_error', 'internal server error')
      }
    },
  )

  app.get(
    '/v1/customers/:id',
    { preHandler: requireTenant('read') },
    async (request, reply) => {
      const customer = await deps.customers.get(
        requestContext(request).tenantId!,
        (request.params as { id: string }).id,
      )
      return customer
        ? reply.send(customer)
        : errorResponse(reply, 404, 'not_found', 'not found')
    },
  )

  app.get(
    '/v1/audit',
    { preHandler: requireTenant('read') },
    async (request, reply) => {
      const limit = Number((request.query as { limit?: string }).limit ?? 100)

      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
        return errorResponse(reply, 400, 'validation_error', 'invalid limit')
      }

      return reply.send(
        (await deps.audit.list(requestContext(request).tenantId!)).slice(0, limit),
      )
    },
  )

  app.get(
    '/v1/audit/verify',
    { preHandler: requireTenant('read') },
    async (request) =>
      deps.audit.verify(requestContext(request).tenantId!),
  )

  for (const route of [
    ['/v1/accounts', ['GET', 'POST']],
    ['/v1/accounts/:id/balances', ['GET']],
    ['/v1/payouts', ['POST']],
    ['/v1/fx/quotes', ['POST']],
    ['/v1/cards', ['POST']],
  ] as const) {
    for (const method of route[1]) {
      app.route({
        method,
        url: route[0],
        preHandler: requireTenant(method === 'GET' ? 'read' : 'write'),
        handler: async (_request, reply) =>
          errorResponse(
            reply,
            501,
            'provider_unverified',
            'not enabled: provider schema unverified',
          ),
      })
    }
  }

  return app
}
