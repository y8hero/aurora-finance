# Supabase/Postgres persistence

Aurora Core is the only application component that connects to Postgres. The
connection is configured with `DATABASE_URL`, loaded through `loadConfig()` and
wrapped as a redacted `Secret`.

## Applying migrations

Apply the files in `db/migrations` in numeric order using the Supabase SQL
editor or an approved migration workflow:

```text
001_tenants.sql
002_provider_customers.sql
003_webhook_events.sql
004_audit_log.sql
005_idempotency_keys.sql
```

The migrations use `IF NOT EXISTS` and replace only the audit mutation
triggers. Review changes in a staging project before applying them to a
production project.

## Security model

Every table enables Row Level Security and intentionally has no policies.
That denies access to Supabase `anon` and `authenticated` roles. The Aurora
server uses the direct database connection role through `DATABASE_URL`; that
role must be protected as a server-only secret and must never be exposed to a
browser or client application.

Tenant filtering remains present in every repository query even though the
direct server role is trusted. This is defense in depth.

## Backup and recovery

Enable Supabase backups and point-in-time recovery appropriate to the
environment. Test restoration and migration replay regularly. Database
backups must be treated as sensitive because they contain raw webhook bodies,
audit metadata, tenant data, and provider identifiers.

## Still unverified

- The exact Supabase connection string format and whether the selected
  connection endpoint requires a provider-specific SSL configuration.
- Production pool sizing and operational limits.
- Supabase role configuration for the direct server connection.
- Retention, archival, and legal hold requirements for raw webhook bodies.
- Whether `gen_random_uuid()` is enabled in the target project; enable the
  required extension or replace the default before applying migration 004.
- Operational behavior and lock timing under the production workload.
- Migration deployment, backup, and restore procedures in the target Supabase
  project.
