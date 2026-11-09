# Supabase/Postgres persistence

Aurora Core is the only application component that connects to Postgres.
The connection is configured with `DATABASE_URL`, loaded through
`loadConfig()` and wrapped as a redacted `Secret`.

## Applying migrations

Apply these files in numeric order in the Supabase SQL editor:

001_tenants.sql, 002_provider_customers.sql, 003_webhook_events.sql, 004_audit_log.sql, 005_idempotency_keys.sql, 006_api_keys.sql, 007_customers.sql.

The migrations are intended for an empty database and are idempotent through
`IF NOT EXISTS`, `CREATE OR REPLACE FUNCTION`, and `DROP TRIGGER IF EXISTS`.

## Security model

Every table enables Row Level Security and intentionally has no policies.
That denies access to Supabase `anon` and `authenticated` roles. Aurora Core
uses only the server-side direct connection role through `DATABASE_URL`.

The fixed system tenant is
00000000-0000-0000-0000-000000000001.

Tenant filtering remains present in repository queries as defense in depth.

## Personal data

The `customers` table contains personal data: names, email, country, KYC
tier, and customer status. Define retention, deletion, legal-hold, and access
procedures before production. No money amounts are stored in this table.

Integration tests using `TEST_DATABASE_URL` must point to a disposable database.
Test rows are intentionally not cleaned up because audit records are append-only
and tenant deletion is constrained by foreign keys.

## TLS and Supabase connection selection

By default the pool requires certificate verification with `rejectUnauthorized: true`.

If `DATABASE_CA_CERT_PATH` is set, it must point to a PEM CA certificate file.
Aurora reads that file only to configure TLS with `ssl.ca`, still using
`rejectUnauthorized: true`.

Obtain Supabase's root certificate from Dashboard > Project Settings >
Database > SSL Configuration.

If the direct database host is unreachable because the environment lacks IPv6,
use Supabase's Session pooler connection string in `DATABASE_URL`. Never log
or expose the connection string.

## Backup and recovery

Enable Supabase backups and point-in-time recovery appropriate to the
environment. Test restoration and migration replay regularly.

## Still unverified

Production pool sizing, Supabase role configuration, retention/legal-hold
details, migration deployment and restore procedures, and production lock
timing remain unverified.
