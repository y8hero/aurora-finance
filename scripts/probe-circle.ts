import { loadConfig } from '../src/config/env'
import { CircleAdapter } from '../src/adapters/circle/CircleAdapter'

const config = loadConfig()
const adapter = new CircleAdapter({
  environment: 'testnet',
  apiKey: config.CIRCLE_API_KEY_TESTNET,
  baseUrl: 'https://api.circle.com',
})

await adapter.checkAuth()
const wallet = await adapter.probeWallets()
const mintMain = await adapter.probeMint('https://api.circle.com')
const mintSandbox = await adapter.probeMint('https://api-sandbox.circle.com')

console.log(JSON.stringify({
  productProbes: {
    walletApi: wallet,
    mintMain,
    mintSandbox,
  },
}, null, 2))
