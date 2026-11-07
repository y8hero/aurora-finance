import pino from 'pino'

export type Logger = pino.Logger

/**
 * Structured JSON logger. Redacts anything that looks like a credential.
 * Secrets should additionally be wrapped in `Secret` so they never reach here as plain strings.
 */
export function createLogger(level: string = 'info'): Logger {
  return pino({
    level,
    base: { service: 'aurora-core', phase: 1 },
    redact: {
      paths: [
        'secret',
        '*.secret',
        'apiKey',
        '*.apiKey',
        'authorization',
        '*.authorization',
        'headers.authorization',
        'headers.Authorization',
        'MAPLERAD_SECRET_KEY',
        'MAPLERAD_SECRET_KEY_SANDBOX',
        'MAPLERAD_SECRET_KEY_LIVE',
        'MAPLERAD_WEBHOOK_SECRET',
        'CIRCLE_API_KEY_TESTNET',
        'CIRCLE_API_KEY_MAINNET',
      ],
      censor: '[redacted]',
    },
  })
}
