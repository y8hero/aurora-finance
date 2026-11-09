The migrations are intended for an empty database and are idempotent through
`IF NOT EXISTS`, `CREATE OR REPLACE FUNCTION`, and `DROP TRIGGER IF EXISTS`.

## Security model

Every table enables Row Level Security and intentionally has no policies.
That denies access to Supabase `anon` and `authenticated` roles. Aurora Core
uses only the server-side direct connection role through `DATABASE_URL`.

The fixed system tenant is:
