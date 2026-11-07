# Aurora Core — Phase 1 skeleton

Provider-agnostic foundation for the Aurora money layer. **No real provider calls exist in this phase.**

## Phase 0 facts applied

- Maplerad uses one HTTPS base URL: `https://api.maplerad.com`; the key decides sandbox/live.
- Maplerad authentication is `Authorization: Bearer <SECRET_KEY>`.
- Maplerad Svix-style webhook signatures are implemented with raw-body signing, Base64 HMAC-SHA256, `whsec_` decoding, five-minute timestamp tolerance, optional IP filtering, and `svix-id` deduplication.
- Maplerad restricted jurisdictions are stored in `src/config/restricted-jurisdictions.json`, with `last_checked: 2026-11-07`.
- Tenant countries, UBO countries, and counterparty countries can be screened before onboarding or payout workflows.
- Money amounts are integer minor-unit strings. Floats and major-unit decimal strings are rejected by `assertIntegerMinorUnitAmount`.
- Reconciliation is modeled as a polling backup. It reports provider-versus-ledger differences and does not credit value from a webhook alone.

## Still unverified

- Maplerad supported countries/currencies per product.
- Exact response schemas, rate limits, and error formats.
- Maplerad webhook event names and payloads.
- `maplerad-node` sandbox behavior.
- Solana support per asset on Maplerad and Circle.
- Circle wallet product and third-party tenant permissions.
- Apple Pay / Google Pay provisioning.
- Maplerad BaaS white-label terms.

## Run

```sh
cp .env.example .env
npm test
npm run typecheck
npm run dev
```

The Maplerad and Circle adapters remain stubs. No live provider SDK or HTTP call is wired.
