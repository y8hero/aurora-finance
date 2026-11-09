CREATE TABLE IF NOT EXISTS webhook_events (
  provider text NOT NULL,
  delivery_id text NOT NULL,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  event_id text NOT NULL,
  event_type text NOT NULL,
  raw_body text NOT NULL,
  raw_body_hash text NOT NULL,
  received_at timestamptz NOT NULL,
  processed_at timestamptz,
  PRIMARY KEY (provider, delivery_id)
);

ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS webhook_events_tenant_idx
  ON webhook_events (tenant_id);
CREATE INDEX IF NOT EXISTS webhook_events_event_idx
  ON webhook_events (provider, event_id);
