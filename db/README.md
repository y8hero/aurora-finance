# Supabase/Postgres persistence

Aurora Core is the only application component that connects to Postgres.
The connection is configured with `DATABASE_URL`, loaded through
`loadConfig()` and wrapped as a redacted `Secret`.

## Applying migrations

Apply these files in numeric order in the Supabase SQL editor:

```text
001_tenants.sql
002_provider_customers.sql
003_webhook_events.sql
004_audit_log.sql
005_idempotency_keys.sql
```

The migrations are intended for an empty database and are idempotent through
`IF NOT EXISTS`, `CREATE OR REPLACE FUNCTION`, and `DROP TRIGGER IF EXISTS`.

## Security model

Every table enables Row Level Security and intentionally has no policies.
That denies access to Supabase `anon` and `authenticated` roles. Aurora Core
uses only the server-side direct connection role through `DATABASE_URL`.

The fixed system tenant is:

```text
00000000-0000-0000-0000-000000000001
```

Tenant filtering remains present in repository queries as defense in depth.

## TLS and Supabase connection selection

By default the pool requires certificate verification with
`rejectUnauthorized: true`.

If `DATABASE_CA_CERT_PATH` is set, it must point to a PEM CA certificate file.
Aurora reads that file only to configure the TLS client and uses it as
`ssl.ca`, still with `rejectUnauthorized: true`.

Obtain Supabase's root certificate from:

```text
Dashboard > Project Settings > Database > SSL Configuration
```

If the direct database host is unreachable because the environment lacks IPv6,
use Supabase's Session pooler connection string in `DATABASE_URL`. Never log
or expose the connection string.

## Backup and recovery

Enable Supabase backups and point-in-time recovery appropriate to the
environment. Test restoration and migration replay regularly. Backups contain
raw webhook bodies, audit metadata, tenant data, and provider identifiers.

## Still unverified

- Production pool sizing and operational limits.
- Supabase role configuration for the direct server connection.
- Retention, archival, and legal-hold requirements for raw webhook bodies.
- Migration deployment, backup, and restore procedures.
- Whether the target Supabase role is permitted to use advisory locks and
  database triggers under its connection role.
- Operational lock timing under production workload.
