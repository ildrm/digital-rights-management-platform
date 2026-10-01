BEGIN;

-- Small, application-encrypted packages may be stored in the existing LTS
-- PostgreSQL cluster instead of an additional object-storage service.
CREATE TABLE drm.package_objects (
  tenant_id uuid NOT NULL REFERENCES drm.tenants(id),
  object_key text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 512),
  package_sha256 bytea NOT NULL CHECK (octet_length(package_sha256) = 32),
  package_bytes integer NOT NULL CHECK (package_bytes BETWEEN 1 AND 104857600),
  body bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_key),
  UNIQUE (object_key),
  CHECK (octet_length(body) = package_bytes)
);
ALTER TABLE drm.package_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.package_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.package_objects
  USING (tenant_id = drm.current_tenant())
  WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
