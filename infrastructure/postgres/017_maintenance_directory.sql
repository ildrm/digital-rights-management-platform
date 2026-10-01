BEGIN;

-- Runtime schedulers need tenant IDs without reading tenant-scoped records.
-- This directory contains IDs only and is not exposed through an HTTP route.
CREATE TABLE drm.maintenance_tenants (
  tenant_id uuid PRIMARY KEY REFERENCES drm.tenants(id) ON DELETE CASCADE
);
INSERT INTO drm.maintenance_tenants(tenant_id) SELECT id FROM drm.tenants;
CREATE FUNCTION drm.register_maintenance_tenant() RETURNS trigger LANGUAGE plpgsql
  SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  INSERT INTO drm.maintenance_tenants(tenant_id) VALUES (NEW.id);
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION drm.register_maintenance_tenant() FROM PUBLIC;
CREATE TRIGGER tenants_maintenance_directory AFTER INSERT ON drm.tenants
  FOR EACH ROW EXECUTE FUNCTION drm.register_maintenance_tenant();

COMMIT;
