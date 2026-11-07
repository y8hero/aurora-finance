# Provider capabilities — Phase 0 facts (as verified so far)

Only facts verified from live provider documentation appear under **Verified**. Everything else is **UNVERIFIED** and must not be assumed in code. Date of Maplerad verification: 2026-11-07.

## Maplerad

### Verified

| Topic | Fact | Source |
|---|---|---|
| Base URL | `https://api.maplerad.com` for **both** sandbox and live. The **key decides the environment**, not the URL. Dashboard: `https://app.maplerad.com` (switch to the sandbox account for sandbox keys). | maplerad.dev/docs/environment |
| Sandbox | Requests never reach banking networks; no real balances or costs. Webhooks fire instantly to the URL set on the business dashboard. Sandbox cannot simulate transfers into virtual accounts end to end. | maplerad.dev/docs/environment, status notice |
| Auth | `Authorization: Bearer <SECRET_KEY>` on every request. HTTPS only. Public keys = frontend/no write (except Checkout); secret keys = full access, server-side only. Missing/invalid auth → 401. Production requires IP whitelisting (else likely 403). "Generate new keys" invalidates all existing keys. | maplerad.dev/docs/authentication |
| Create customer (Tier 0) | `POST /v1/customers` with required `first_name`, `last_name`, `email`, `country`. Returns a customer ID. **Response schema UNVERIFIED** (page did not render). | maplerad.dev/reference/create-a-customer |
| KYC tiers | Tier 0 (name, email): Bills, FX, Transfers. Tier 1 (+phone, DOB, ID number e.g. BVN/SSN, home address): Collections, Issuing. Tier 2 (+identity document e.g. NIN): all services. Upgrade/Enroll/Update Customer endpoints exist. | maplerad.dev/docs/customers |
| Webhook signatures | Svix-style. Headers `svix-id`, `svix-timestamp` (unix seconds), `svix-signature` (space-delimited `v1,<base64>` entries). Signed content `{svix-id}.{svix-timestamp}.{raw body}`. Secret `whsec_<base64 key>`: strip prefix, Base64-decode, HMAC-SHA256, Base64 output. Constant-time compare against any `v1` entry. Reject stale timestamps (no documented window; Aurora uses 5 min). Ten published source IPs may be allow-listed (copy from page). Ignore the page's Go sample. | maplerad.dev/docs/verifying-webhooks |
| USD wallets | SPEND wallet (card transactions only) and TREASURY wallet (FX, stablecoin, deposits, transfers, everything else). Move funds via the wallet-funding endpoint. API-only for now. | Maplerad status notice, April 2026 |
| SDK | Official Node SDK `maplerad-node` (constructor: secret key + environment string). Not installed in Aurora yet. | SDK listing |
| API areas | Customer, Collections, Transfers, Bills, Wallets, Issuing, Identity, Transactions, Counterparty, FX, Institutions, Misc (incl. Get all Countries). FX = quote, then exchange by quote reference. | maplerad.dev |

### Unverified (resolve with a sandbox call or by reading the page)

- Supported countries and currencies per product (call Get all Countries / Get currencies in sandbox; read Collections > Restricted Jurisdictions).
- Exact response schemas, rate limits, error formats.
- Webhook event names and payloads (maplerad.dev/docs/overview-7).
- Whether sandbox keys work with `maplerad-node` and environment string `sandbox`.
- Which tier unlocks the Wallets endpoints (not listed in the tier table).
- Field names for the Upgrade Customer (Tier 1 / Tier 2) endpoints.
- Solana support per asset (USDC, USDT, PYUSD).
- Apple Pay / Google Pay provisioning on issued cards.
- Whether BaaS terms allow white-labelling to other businesses, and in which countries.

**Do not use** `docs.maple.inc` / `api.maple.inc`: different company (restaurant ordering API).

## Circle

### Verified

- Auth is a Bearer API key. Testnet and mainnet use **separate keys** and may use different base URLs.
- CCTP V2 for cross-chain USDC/EURC.
- Never hardcode USDC/EURC contract addresses; use Circle's address reference / MCP.
- Official skills: `github.com/circlefin/skills`.

### Unverified (blocking)

- **Which Circle wallet product Walter's account uses** (custodied vs developer-controlled). Walter must check the Circle console. If developer-controlled, Aurora would hold keys, contradicting the no-custody model — no wallet feature may be built until answered.
- Testnet/mainnet base URLs; whether the account tier enables Wallets + CCTP V2 on mainnet.
- Solana support per asset (USDC, EURC).
- Permission for a platform with third-party tenants under TBC's account.

## Capability matrix (Phase 1 code status)

| Capability | Provider | Code status |
|---|---|---|
| Auth check | Maplerad | Header format verified; **no live call** (no auth-check endpoint confirmed) |
| Create customer | Maplerad | Request builder verified (`POST /v1/customers`); response schema UNVERIFIED → still throws |
| KYC tiers | Maplerad | Tier table verified; gating implemented in core and mock |
| Webhook verification | Maplerad | Scheme verified and implemented (`MapleradWebhookVerifier`); event payloads UNVERIFIED → route disabled |
| Virtual accounts / collections | Maplerad | UNVERIFIED |
| FX quote/exchange | Maplerad | Flow verified (quote → exchange by ref); endpoints UNVERIFIED |
| Transfers / payouts | Maplerad | UNVERIFIED |
| Card issuing | Maplerad | UNVERIFIED |
| Wallets / CCTP | Circle | UNVERIFIED (blocked on product confirmation) |
