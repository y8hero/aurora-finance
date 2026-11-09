CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  country text NOT NULL,
  status text NOT NULL CHECK (status IN ('system', 'active', 'suspended', 'closed')),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS tenants_country_idx ON tenants (country);

INSERT INTO tenants (id, slug, name, country, status)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'platform',
  'platform',
  'ZZ',
  'system'
)
ON CONFLICT (id) DO NOTHING;
