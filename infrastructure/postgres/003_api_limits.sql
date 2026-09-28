BEGIN;

CREATE TABLE drm.api_rate_windows (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN ('device-challenge', 'license-issue')),
  window_start timestamptz NOT NULL,
  request_count integer NOT NULL CHECK (request_count > 0),
  PRIMARY KEY (tenant_id, user_id, operation, window_start),
  FOREIGN KEY (tenant_id, user_id) REFERENCES drm.users (tenant_id, id)
);
CREATE INDEX api_rate_windows_expiry ON drm.api_rate_windows (window_start);
ALTER TABLE drm.api_rate_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.api_rate_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.api_rate_windows
  USING (tenant_id = drm.current_tenant())
  WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
