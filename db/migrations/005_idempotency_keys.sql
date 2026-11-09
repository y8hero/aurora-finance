CREATE TABLE IF NOT EXISTS idempotency_keys (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  key text NOT NULL,
  request_hash text NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key),
  UNIQUE (tenant_id, key)
);

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idempotency_keys_tenant_idx
  ON idempotency_keys (tenant_id);
