import { isIP } from 'node:net'
import { z } from 'zod'

const MAX_SECRET_LENGTH = 4096
const MAX_URL_LENGTH = 2048
const MAX_IP_LIST_LENGTH = 4096

/**
 * A secret value that cannot be stringified or JSON-serialised by accident.
 * Call `.reveal()` only at the point of use (e.g. building an Authorization header).
 */
export class Secret {
  readonly #value: string

  constructor(value: string) {
    this.#value = value
  }

  reveal(): string {
    return this.#value
  }

  toString(): string {
    return '[redacted]'
  }

  toJSON(): string {
    return '[redacted]'
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return '[redacted]'
  }
}

export const DEFAULT_MAPLERAD_BASE_URL = 'https://api.maplerad.com'

const optionalSecret = z
  .string()
  .trim()
  .max(MAX_SECRET_LENGTH)
  .optional()
  .transform((value) => (value && value.length > 0 ? new Secret(value) : undefined))

const optionalWhsecSecret = z
  .string()
  .trim()
  .max(MAX_SECRET_LENGTH)
  .optional()
  .refine(
    (value) => value === undefined || value.length === 0 || value.startsWith('whsec_'),
    {
      message: 'Maplerad webhook signing secret must start with "whsec_"',
    },
  )
  .transform((value) => (value && value.length > 0 ? new Secret(value) : undefined))

const optionalUrl = z
  .string()
  .trim()
  .max(MAX_URL_LENGTH)
  .optional()
  .transform((value) => (value && value.length > 0 ? value : undefined))
  .pipe(z.string().url().optional())

const mapleradBaseUrl = z
  .string()
  .trim()
  .max(MAX_URL_LENGTH)
  .optional()
  .transform((value) => (value && value.length > 0 ? value : DEFAULT_MAPLERAD_BASE_URL))
  .pipe(z.string().url().startsWith('https://', { message: 'Maplerad requires HTTPS' }))

const ipList = z
  .string()
  .trim()
  .max(MAX_IP_LIST_LENGTH)
  .optional()
  .transform((value) =>
    value
      ? value
          .split(',')
          .map((part) => part.trim())
          .filter((part) => part.length > 0)
      : [],
  )
  .refine((ips) => ips.length <= 32, {
    message: 'must contain no more than 32 IP addresses',
  })
  .refine((ips) => ips.every((ip) => isIP(ip) !== 0), {
    message: 'must be a comma-separated list of IPv4/IPv6 addresses',
  })

const schema = z
  .object({
    AURORA_ENV: z.enum(['development', 'test', 'sandbox']).default('development'),

    PORT: z.coerce.number().int().positive().max(65535).default(3000),

    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),

    MAPLERAD_ENV: z.enum(['sandbox']).default('sandbox'),
    MAPLERAD_BASE_URL: mapleradBaseUrl,
    MAPLERAD_SECRET_KEY_SANDBOX: optionalSecret,
    MAPLERAD_WEBHOOK_SECRET: optionalWhsecSecret,
    MAPLERAD_WEBHOOK_ALLOWED_IPS: ipList,

    CIRCLE_ENV: z.enum(['testnet']).default('testnet'),
    CIRCLE_API_KEY_TESTNET: optionalSecret,
    CIRCLE_API_KEY_MAINNET: optionalSecret,
    CIRCLE_BASE_URL_TESTNET: optionalUrl,
    CIRCLE_BASE_URL_MAINNET: optionalUrl,

    MOCK_WEBHOOK_SECRET: z
      .string()
      .min(8)
      .max(MAX_SECRET_LENGTH)
      .default('dev-only-mock-secret-change-me'),
  })
  .strict()

export type AppConfig = Readonly<z.infer<typeof schema>>

export class ConfigError extends Error {
  override name = 'ConfigError'
}

function nonEmpty(value: string | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0
}

/**
 * Empty legacy variables commonly produced by .env templates are treated as
 * unset before strict validation. Non-empty values are rejected explicitly
 * below with migration/safety messages.
 */
function removeEmptyLegacyMapleradKeys(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = { ...env }

  for (const key of ['MAPLERAD_SECRET_KEY_LIVE', 'MAPLERAD_SECRET_KEY'] as const) {
    if (typeof sanitized[key] === 'string' && sanitized[key].trim().length === 0) {
      delete sanitized[key]
    }
  }

  return sanitized
}

/**
 * Selects only Aurora-owned environment variables before passing the object to
 * the strict Zod schema. process.env also contains Windows, npm, and shell
 * variables, so validating it directly would incorrectly fail with
 * "Unrecognized keys".
 */
const CONFIG_KEYS = [
  'AURORA_ENV',
  'PORT',
  'LOG_LEVEL',
  'MAPLERAD_ENV',
  'MAPLERAD_BASE_URL',
  'MAPLERAD_SECRET_KEY_SANDBOX',
  'MAPLERAD_WEBHOOK_SECRET',
  'MAPLERAD_WEBHOOK_ALLOWED_IPS',
  'CIRCLE_ENV',
  'CIRCLE_API_KEY_TESTNET',
  'CIRCLE_API_KEY_MAINNET',
  'CIRCLE_BASE_URL_TESTNET',
  'CIRCLE_BASE_URL_MAINNET',
  'MOCK_WEBHOOK_SECRET',
] as const

function selectConfigEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const selected: NodeJS.ProcessEnv = {}

  for (const key of CONFIG_KEYS) {
    const value = env[key]
    if (value !== undefined) {
      selected[key] = value
    }
  }

  return selected
}

/**
 * Loads config from an environment map. Pure: pass process.env in production
 * code, or a plain object in tests.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  if (env.AURORA_ENV === 'production') {
    throw new ConfigError(
      'Phase 1 skeleton refuses AURORA_ENV=production. No production until Phase 4+ and legal sign-off.',
    )
  }

  if (env.MAPLERAD_ENV === 'live') {
    throw new ConfigError('Phase 1 skeleton refuses MAPLERAD_ENV=live. Sandbox only.')
  }

  if (nonEmpty(env.MAPLERAD_SECRET_KEY_LIVE)) {
    throw new ConfigError(
      'Phase 1 skeleton refuses a Maplerad LIVE key (MAPLERAD_SECRET_KEY_LIVE). At Maplerad the key decides the environment; remove it until Phase 4+.',
    )
  }

  if (nonEmpty(env.MAPLERAD_SECRET_KEY)) {
    throw new ConfigError(
      'MAPLERAD_SECRET_KEY was renamed to MAPLERAD_SECRET_KEY_SANDBOX (one base URL; the key decides the environment). Update .env.',
    )
  }

  if (env.CIRCLE_ENV === 'mainnet') {
    throw new ConfigError('Phase 1 skeleton refuses CIRCLE_ENV=mainnet. Testnet only.')
  }

  const sanitized = removeEmptyLegacyMapleradKeys(env)
  const parsed = schema.safeParse(selectConfigEnvironment(sanitized))

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ')

    throw new ConfigError(`Invalid configuration: ${issues}`)
  }

  return Object.freeze(parsed.data)
}
