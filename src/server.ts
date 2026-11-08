import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { loadConfig } from './config/env'
import { createLogger } from './logging/logger'
import { InMemoryAuditLog } from './core/audit/auditLog'
import { tenantId, type ProviderName } from './core/types'
import { MockAdapter, mockWebhookParser } from './adapters/mock/MockAdapter'
import { MapleradAdapter } from './adapters/maplerad/MapleradAdapter'
import { CircleAdapter } from './adapters/circle/CircleAdapter'
import { InMemoryWebhookEventStore } from './webhooks/eventStore'
import { VerifierRegistry } from './webhooks/signature'
import { WebhookReceiver, type WebhookParser, type WebhookTenantResolver } from './webhooks/receiver'

const config = loadConfig()
const logger = createLogger(config.LOG_LEVEL)
const audit = new InMemoryAuditLog()
const eventStore = new InMemoryWebhookEventStore()

const mock = new MockAdapter(config.MOCK_WEBHOOK_SECRET)
const maplerad = new MapleradAdapter({
  environment: config.MAPLERAD_ENV,
  baseUrl: config.MAPLERAD_BASE_URL,
  secretKey: config.MAPLERAD_SECRET_KEY_SANDBOX,
  webhookSecret: config.MAPLERAD_WEBHOOK_SECRET,
  allowedWebhookIps: config.MAPLERAD_WEBHOOK_ALLOWED_IPS,
})
const circle = new CircleAdapter({
  environment: config.CIRCLE_ENV,
  apiKey: config.CIRCLE_API_KEY_TESTNET,
  baseUrl: config.CIRCLE_BASE_URL_TESTNET,
})

const verifiers = new VerifierRegistry().register(mock.verifier)
if (maplerad.webhookVerifier) verifiers.register(maplerad.webhookVerifier)

const parsers = new Map<ProviderName, WebhookParser>([['mock', mockWebhookParser]])
const tenantResolver: WebhookTenantResolver = mock.tenantResolver
const receiver = new WebhookReceiver({
  verifiers,
  parsers,
  tenantResolver,
  store: eventStore,
  audit,
  logger,
})

const PROVIDERS: ReadonlySet<string> = new Set<ProviderName>(['maplerad', 'circle', 'mock'])
const MAX_BODY_BYTES = 1_000_000

function readBody(req: IncomingMessage): Promise<string> {
  const declaredLength = req.headers['content-length']

  if (declaredLength !== undefined) {
    const length = Number(declaredLength)
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_BODY_BYTES) {
      return Promise.reject(new Error('request body exceeds the 1 MB limit'))
    }
  }

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    let settled = false

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      reject(error)
      req.destroy()
    }

    req.on('data', (chunk: Buffer) => {
      if (settled) return
      size += chunk.length

      if (size > MAX_BODY_BYTES) {
        fail(new Error('request body exceeds the 1 MB limit'))
        return
      }

      chunks.push(chunk)
    })

    req.on('end', () => {
      if (!settled) {
        settled = true
        resolve(Buffer.concat(chunks).toString('utf8'))
      }
    })

    req.on('error', (error) => {
      fail(error instanceof Error ? error : new Error(String(error)))
    })
  })
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const encoded = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(encoded),
  })
  res.end(encoded)
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost')

  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, {
      ok: true,
      phase: 1,
      env: config.AURORA_ENV,
      adapters: {
        mock: 'active',
        maplerad: {
          environment: maplerad.environment,
          baseUrl: maplerad.baseUrl,
          status: 'stub — no live calls',
          secretConfigured: maplerad.hasSecretKey,
        },
        circle: {
          environment: circle.environment,
          status: 'UNVERIFIED stub',
          apiKeyConfigured: circle.hasApiKey,
        },
      },
    })
  }

  const match = url.pathname.match(/^\/webhooks\/([a-z]+)(?:\/[A-Za-z0-9_-]+)?$/)

  if (req.method === 'POST' && match) {
    const providerRaw = match[1]

    if (!providerRaw || !PROVIDERS.has(providerRaw)) {
      return json(res, 404, { error: 'not found' })
    }

    const provider = providerRaw as ProviderName

    try {
      const rawBody = await readBody(req)
      const headers = Object.fromEntries(
        Object.entries(req.headers).map(([key, value]) => [key.toLowerCase(), value]),
      )

      if (provider !== 'mock') {
        logger.warn({ provider }, 'provider webhook route is unverified')
        return json(res, 501, { error: 'provider webhook unavailable' })
      }

      const outcome = await receiver.receive({
        provider,
        rawBody,
        headers,
        ...(req.socket.remoteAddress ? { sourceIp: req.socket.remoteAddress } : {}),
      })

      if (outcome.status === 'rejected') {
        logger.warn({ provider, reason: outcome.reason }, 'webhook rejected')
        return json(res, 401, { error: 'unauthorized' })
      }

      return json(res, 200, {
        status: outcome.status,
        svixId: outcome.record.svix_id,
        eventId: outcome.record.event_id,
        tenantId: outcome.record.tenant_id,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)

      if (message === 'request body exceeds the 1 MB limit') {
        logger.warn({ provider }, 'request body too large')
        return json(res, 413, { error: 'request too large' })
      }

      logger.error({ err: error, provider }, 'internal webhook error')
      return json(res, 500, { error: 'internal server error' })
    }
  }

  return json(res, 404, { error: 'not found' })
})

server.listen(config.PORT, () => {
  logger.info(
    { port: config.PORT, env: config.AURORA_ENV },
    'Aurora Core Phase 1 skeleton listening. Only mock is active; Maplerad/Circle make no calls.',
  )
})
