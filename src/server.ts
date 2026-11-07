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
import { WebhookReceiver, type WebhookParser } from './webhooks/receiver'

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
if (maplerad.webhookVerifier) {
  verifiers.register(maplerad.webhookVerifier)
}

const parsers = new Map<ProviderName, WebhookParser>([
  ['mock', mockWebhookParser],
])
const receiver = new WebhookReceiver({
  verifiers,
  parsers,
  store: eventStore,
  audit,
  logger,
})

const PROVIDERS: ReadonlySet<string> = new Set<ProviderName>([
  'maplerad',
  'circle',
  'mock',
])

const MAX_BODY_BYTES = 1_000_000

function readBody(req: IncomingMessage): Promise<string> {
  const declaredLength = req.headers['content-length']

  if (declaredLength !== undefined) {
    const parsedLength = Number(declaredLength)

    if (
      !Number.isSafeInteger(parsedLength) ||
      parsedLength < 0 ||
      parsedLength > MAX_BODY_BYTES
    ) {
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
      if (settled) return
      settled = true
      resolve(Buffer.concat(chunks).toString('utf8'))
    })

    req.on('error', (error) => {
      fail(error instanceof Error ? error : new Error(String(error)))
    })
  })
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(JSON.stringify(body)),
  })
  res.end(JSON.stringify(body))
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
          webhookVerifierConfigured: maplerad.webhookVerifier !== undefined,
        },
        circle: {
          environment: circle.environment,
          status: 'UNVERIFIED stub',
          apiKeyConfigured: circle.hasApiKey,
        },
      },
    })
  }

  const match = url.pathname.match(/^\/webhooks\/([a-z]+)\/([A-Za-z0-9_-]+)$/)

  if (req.method === 'POST' && match) {
    const [, providerRaw, tenantRaw] = match

    if (!providerRaw || !PROVIDERS.has(providerRaw)) {
      return json(res, 404, { error: 'unknown provider' })
    }

    const provider = providerRaw as ProviderName

    if (provider !== 'mock') {
      return json(res, 501, {
        error: `UNVERIFIED: complete Phase 0 — ${provider} event names/payloads are not confirmed`,
      })
    }

    let scopedTenant
    try {
      scopedTenant = tenantId(tenantRaw ?? '')
    } catch {
      return json(res, 400, { error: 'invalid tenant id' })
    }

    try {
      // The body limit is enforced before JSON parsing, signature parsing,
      // webhook schema parsing, or any downstream validation.
      const rawBody = await readBody(req)
      const headers = Object.fromEntries(
        Object.entries(req.headers).map(([key, value]) => [
          key.toLowerCase(),
          value,
        ]),
      )

      const outcome = await receiver.receive({
        provider,
        tenantId: scopedTenant,
        rawBody,
        headers,
        ...(req.socket.remoteAddress
          ? { sourceIp: req.socket.remoteAddress }
          : {}),
      })

      if (outcome.status === 'rejected') {
        return json(res, 401, {
          status: 'rejected',
          reason: outcome.reason,
        })
      }

      // HTTP 200 is returned only after event insertion and audit completion.
      return json(res, 200, {
        status: outcome.status,
        svixId: outcome.record.svix_id,
        eventId: outcome.record.event_id,
      })
    } catch (error) {
      logger.error({ err: error }, 'webhook handling failed')
      return json(res, 413, {
        error: (error as Error).message,
      })
    }
  }

  return json(res, 404, { error: 'not found' })
})

server.listen(config.PORT, () => {
  logger.info(
    {
      port: config.PORT,
      env: config.AURORA_ENV,
      mapleradEnv: config.MAPLERAD_ENV,
      mapleradBaseUrl: config.MAPLERAD_BASE_URL,
      circleEnv: config.CIRCLE_ENV,
    },
    'Aurora Core Phase 1 skeleton listening. Only mock is active; Maplerad/Circle make no calls.',
  )
})
