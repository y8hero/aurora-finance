CREATE TABLE IF NOT EXISTS provider_customers (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  provider text NOT NULL,
  provider_customer_id text NOT NULL,
  kyc_tier smallint NOT NULL CHECK (kyc_tier BETWEEN 0 AND 2),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, provider_customer_id)
);

ALTER TABLE provider_customers ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS provider_customers_tenant_idx
  ON provider_customers (tenant_id);
