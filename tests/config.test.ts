import { describe, expect, it } from 'vitest'
import { ConfigError, DEFAULT_MAPLERAD_BASE_URL, loadConfig, Secret } from '../src/config/env'

describe('config', () => {
  it('loads with defaults and no provider secrets', () => {
    const cfg = loadConfig({})
    expect(cfg.AURORA_ENV).toBe('development')
    expect(cfg.MAPLERAD_ENV).toBe('sandbox')
    expect(cfg.MAPLERAD_BASE_URL).toBe('https://api.maplerad.com')
    expect(DEFAULT_MAPLERAD_BASE_URL).toBe('https://api.maplerad.com')
    expect(cfg.MAPLERAD_SECRET_KEY_SANDBOX).toBeUndefined()
    expect(cfg.MAPLERAD_WEBHOOK_SECRET).toBeUndefined()
    expect(cfg.MAPLERAD_WEBHOOK_ALLOWED_IPS).toEqual([])
    expect(cfg.CIRCLE_ENV).toBe('testnet')
  })

  it('refuses production, live and mainnet in Phase 1', () => {
    expect(() => loadConfig({ AURORA_ENV: 'production' })).toThrow(ConfigError)
    expect(() => loadConfig({ MAPLERAD_ENV: 'live' })).toThrow(ConfigError)
    expect(() => loadConfig({ CIRCLE_ENV: 'mainnet' })).toThrow(ConfigError)
  })

  it('refuses a Maplerad live key outright (the key decides the environment)', () => {
    expect(() => loadConfig({ MAPLERAD_SECRET_KEY_LIVE: 'sk_live_anything' })).toThrow(/LIVE/)
    // An empty slot in .env is harmless.
    expect(() => loadConfig({ MAPLERAD_SECRET_KEY_LIVE: '' })).not.toThrow()
  })

  it('refuses the pre-facts-pack variable name so stale .env files fail loudly', () => {
    expect(() => loadConfig({ MAPLERAD_SECRET_KEY: 'sk_test_old' })).toThrow(/renamed/)
    expect(() => loadConfig({ MAPLERAD_SECRET_KEY: '' })).not.toThrow()
  })

  it('uses one Maplerad base URL and insists on https', () => {
    expect(loadConfig({ MAPLERAD_BASE_URL: '' }).MAPLERAD_BASE_URL).toBe('https://api.maplerad.com')
    expect(loadConfig({ MAPLERAD_BASE_URL: 'https://api.maplerad.com' }).MAPLERAD_BASE_URL).toBe('https://api.maplerad.com')
    expect(() => loadConfig({ MAPLERAD_BASE_URL: 'http://api.maplerad.com' })).toThrow(ConfigError)
    expect(() => loadConfig({ MAPLERAD_BASE_URL: 'not a url' })).toThrow(ConfigError)
  })

  it('requires the Maplerad webhook secret to start with whsec_', () => {
    expect(() => loadConfig({ MAPLERAD_WEBHOOK_SECRET: 'abc123' })).toThrow(/whsec_/)
    const cfg = loadConfig({ MAPLERAD_WEBHOOK_SECRET: 'whsec_dGVzdA==' })
    expect(cfg.MAPLERAD_WEBHOOK_SECRET).toBeInstanceOf(Secret)
    expect(String(cfg.MAPLERAD_WEBHOOK_SECRET)).toBe('[redacted]')
  })

  it('parses the optional Maplerad webhook IP allow-list', () => {
    expect(loadConfig({ MAPLERAD_WEBHOOK_ALLOWED_IPS: ' 203.0.113.10, 203.0.113.11 ,2001:db8::1 ' }).MAPLERAD_WEBHOOK_ALLOWED_IPS).toEqual([
      '203.0.113.10',
      '203.0.113.11',
      '2001:db8::1',
    ])
    expect(() => loadConfig({ MAPLERAD_WEBHOOK_ALLOWED_IPS: '203.0.113.10,not-an-ip' })).toThrow(ConfigError)
  })

  it('wraps secrets so they cannot leak via toString/JSON', () => {
    const cfg = loadConfig({ MAPLERAD_SECRET_KEY_SANDBOX: 'sk_test_abc', CIRCLE_API_KEY_TESTNET: 'TEST_API_KEY:x:y' })
    expect(cfg.MAPLERAD_SECRET_KEY_SANDBOX).toBeInstanceOf(Secret)
    expect(String(cfg.MAPLERAD_SECRET_KEY_SANDBOX)).toBe('[redacted]')
    expect(JSON.stringify({ k: cfg.CIRCLE_API_KEY_TESTNET })).toBe('{"k":"[redacted]"}')
    expect(cfg.MAPLERAD_SECRET_KEY_SANDBOX?.reveal()).toBe('sk_test_abc')
  })

  it('rejects invalid Circle base URLs', () => {
    expect(() => loadConfig({ CIRCLE_BASE_URL_TESTNET: 'not a url' })).toThrow(ConfigError)
  })
})
