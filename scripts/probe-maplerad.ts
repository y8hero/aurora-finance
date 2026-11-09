import { mkdir, writeFile } from 'node:fs/promises'
import { loadConfig } from '../src/config/env'
import { MapleradAdapter } from '../src/adapters/maplerad/MapleradAdapter'

const config = loadConfig()
const adapter = new MapleradAdapter({
  environment: 'sandbox',
  baseUrl: config.MAPLERAD_BASE_URL,
  secretKey: config.MAPLERAD_SECRET_KEY_SANDBOX,
  webhookSecret: config.MAPLERAD_WEBHOOK_SECRET,
  allowedWebhookIps: config.MAPLERAD_WEBHOOK_ALLOWED_IPS,
})

await adapter.checkAuth()
const countries = await adapter.probeCountries()
const currencies = await adapter.probeCurrencies()

await mkdir('docs/probes', { recursive: true })
await writeFile('docs/probes/maplerad-countries.json', JSON.stringify(countries.body, null, 2) + '\n', 'utf8')
await writeFile('docs/probes/maplerad-currencies.json', JSON.stringify(currencies.body, null, 2) + '\n', 'utf8')

console.log('Maplerad probes saved: countries, currencies')
