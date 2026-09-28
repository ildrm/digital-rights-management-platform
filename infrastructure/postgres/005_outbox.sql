BEGIN;

CREATE TABLE drm.outbox_events (
  tenant_id uuid NOT NULL REFERENCES drm.tenants(id),
  id uuid NOT NULL,
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
  aggregate_id uuid NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  claimed_by text,
  claimed_until timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  CHECK ((claimed_by IS NULL) = (claimed_until IS NULL))
);
CREATE INDEX outbox_ready ON drm.outbox_events (tenant_id, available_at, created_at)
  WHERE delivered_at IS NULL;

ALTER TABLE drm.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.outbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.outbox_events
  USING (tenant_id = drm.current_tenant())
  WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
