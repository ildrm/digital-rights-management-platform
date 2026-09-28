BEGIN;

CREATE TABLE drm.asset_packages (
  tenant_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  asset_version integer NOT NULL CHECK (asset_version > 0),
  rendition_id uuid NOT NULL,
  object_key text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 512),
  package_sha256 bytea NOT NULL CHECK (octet_length(package_sha256) = 32),
  package_bytes integer NOT NULL CHECK (package_bytes > 0),
  mime_type text NOT NULL CHECK (length(mime_type) BETWEEN 1 AND 256),
  manifest_signing_key_id text NOT NULL CHECK (length(manifest_signing_key_id) BETWEEN 1 AND 512),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, asset_id, asset_version, rendition_id),
  UNIQUE (object_key),
  FOREIGN KEY (tenant_id, asset_id, asset_version, rendition_id)
    REFERENCES drm.rendition_keys (tenant_id, asset_id, asset_version, rendition_id)
);

CREATE TRIGGER asset_packages_immutable BEFORE UPDATE OR DELETE ON drm.asset_packages
  FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();
ALTER TABLE drm.asset_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.asset_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.asset_packages
  USING (tenant_id = drm.current_tenant())
  WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
