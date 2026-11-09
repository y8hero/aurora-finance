CREATE TABLE IF NOT EXISTS customers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  external_ref text,
  first_name text NOT NULL,
  last_name text NOT NULL,
  email text NOT NULL,
  country char(2) NOT NULL,
  kyc_tier smallint NOT NULL DEFAULT 0 CHECK (kyc_tier BETWEEN 0 AND 2),
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX IF NOT EXISTS customers_tenant_external_ref_uq
  ON customers (tenant_id, external_ref)
  WHERE external_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS customers_tenant_idx
  ON customers (tenant_id);
