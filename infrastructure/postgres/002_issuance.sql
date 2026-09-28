BEGIN;

CREATE TABLE drm.rendition_keys (
  tenant_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  asset_version integer NOT NULL,
  rendition_id uuid NOT NULL,
  target text NOT NULL CHECK (target IN ('secureViewer', 'publication', 'software', 'remoteExecution', 'widevine', 'fairplay', 'playready')),
  key_reference text NOT NULL CHECK (length(key_reference) BETWEEN 1 AND 512),
  status text NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, asset_id, asset_version, rendition_id),
  FOREIGN KEY (tenant_id, asset_id, asset_version) REFERENCES drm.asset_versions (tenant_id, asset_id, version)
);

CREATE TABLE drm.device_activations (
  tenant_id uuid NOT NULL,
  entitlement_id uuid NOT NULL,
  device_id uuid NOT NULL,
  activated_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  PRIMARY KEY (tenant_id, entitlement_id, device_id),
  FOREIGN KEY (tenant_id, entitlement_id) REFERENCES drm.entitlements (tenant_id, id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES drm.devices (tenant_id, id)
);
CREATE INDEX active_devices_for_entitlement ON drm.device_activations (tenant_id, entitlement_id) WHERE released_at IS NULL;

ALTER TABLE drm.rendition_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.device_activations ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.rendition_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.device_activations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.rendition_keys USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.device_activations USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
