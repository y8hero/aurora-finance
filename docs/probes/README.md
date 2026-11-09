# Sandbox probe observations

These are **UNVERIFIED reference observations** captured from sandbox/testnet probes. They are not production capability claims and must not be used to enable live money movement without confirmation from current live documentation and provider support.

No secrets, authorization headers, personal data, identifiers, addresses, balances, or full private response values are recorded here.

## Maplerad

### Observed sandbox currencies

The sandbox key exposed these currency/asset codes:

```text
NGN USD GHS KES TZS UGX MWK MZN PYUSD RWF CDF ZAR SLE LRD XAF XOF USDT USDC
```

The sandbox response did **not** offer:

```text
EUR GBP
```

This is sandbox-only reference data. It must be confirmed for the live environment before any live capability decision.

The application currency guard is intentionally marked unverified and is fail-closed for currencies outside this observed sandbox list. This allow-list is not evidence that every listed asset is supported for every Maplerad product, account type, country, rail, or transaction direction.

### Countries endpoint is not a coverage list

The `/v1/countries` response included restricted jurisdictions, including examples such as:

```text
HT PK CD UA
```

Therefore `/v1/countries` must not be treated as Maplerad’s supported-country or product-coverage list.

The authoritative coverage configuration remains:

```json
{
  "verified": false,
  "verified_codes": []
}
```

Country/product coverage remains UNVERIFIED and must be obtained from Maplerad’s verified coverage list and product-specific documentation.

## Circle

### Wallets

The Wallets API returned HTTP `200` with the testnet key.

This confirms only that the tested key could reach the probed Wallets endpoint. It does not identify the complete account product, custody model, tenant permissions, supported assets, chain support, or production availability.

### Mint

The Circle Mint balance probe returned:

| Host | Result |
|---|---:|
| `api.circle.com` | HTTP `403` |
| `api-sandbox.circle.com` | HTTP `401` |

Interpretation: the tested key is not a usable Circle Mint key for these probes. This does not establish whether Mint is unavailable to the account generally, whether another account/key is required, or whether the response reflects environment or permission differences.

## Required follow-up

- Confirm every listed Maplerad currency/asset for live and per-product support.
- Obtain Maplerad’s verified country/product coverage list.
- Confirm Circle’s account product and custody model in the Circle console.
- Confirm Circle Wallets permissions, supported assets, chains, and tenant/platform permissions.
- Do not treat these observations as authorization to enable production calls.
