import { createDatabasePool, closeDatabasePool } from './db/pool'
import { loadConfig } from './config/env'
import { createLogger } from './logging/logger'
import { InMemoryAuditLog } from './core/audit/auditLog'
import { InMemoryTenantRepository } from './core/tenants'
import {
  InMemoryApiKeyRepository,
  InMemoryCustomerRepository,
  PostgresApiKeyRepository,
  PostgresCustomerRepository,
  PostgresTenantRepository,
} from './db/tenantRepositories'
import { ApiKeyService } from './core/apiKeys'
import { IdempotencyStore } from './core/idempotency'
import { TokenBucketRateLimiter } from './core/rateLimiter'
import { MockAdapter, mockWebhookParser } from './adapters/mock/MockAdapter'
import { InMemoryWebhookEventStore } from './webhooks/eventStore'
import { VerifierRegistry } from './webhooks/signature'
import { WebhookReceiver } from './webhooks/receiver'
import { buildApp } from './app'

const config = loadConfig()
const logger = createLogger(config.LOG_LEVEL)
const pool = createDatabasePool(config)
const audit = new InMemoryAuditLog()
const tenants = pool
  ? new PostgresTenantRepository(pool)
  : new InMemoryTenantRepository()
const apiKeys = pool
  ? new PostgresApiKeyRepository(pool)
  : new InMemoryApiKeyRepository()
const customers = pool
  ? new PostgresCustomerRepository(pool)
  : new InMemoryCustomerRepository()
const mock = new MockAdapter(config.MOCK_WEBHOOK_SECRET)
const receiver = new WebhookReceiver({
  verifiers: new VerifierRegistry().register(mock.verifier),
  parsers: new Map([['mock', mockWebhookParser]]),
  tenantResolver: mock.tenantResolver,
  store: new InMemoryWebhookEventStore(),
  audit,
  logger,
})

const app = buildApp({
  config,
  logger,
  audit,
  tenants,
  apiKeys,
  customers,
  apiKeyService: new ApiKeyService(apiKeys),
  receiver,
  idempotency: new IdempotencyStore(),
  tenantLimiter: new TokenBucketRateLimiter(60, 1),
  ipLimiter: new TokenBucketRateLimiter(120, 2),
  ...(config.AURORA_ADMIN_API_KEY
    ? { adminKey: config.AURORA_ADMIN_API_KEY }
    : {}),
})

const shutdown = async (signal: string): Promise<void> => {
  logger.info({ signal }, 'shutting down')
  await app.close()
  await closeDatabasePool(pool)
  process.exitCode = 0
}

process.once('SIGINT', () => void shutdown('SIGINT'))
process.once('SIGTERM', () => void shutdown('SIGTERM'))

await app.listen({ port: config.PORT, host: '0.0.0.0' })
