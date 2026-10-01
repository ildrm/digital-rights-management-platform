BEGIN;

CREATE TABLE drm.user_roles (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'creator', 'customer')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,user_id,role),
  FOREIGN KEY (tenant_id,user_id) REFERENCES drm.users(tenant_id,id)
);
INSERT INTO drm.user_roles(tenant_id,user_id,role) SELECT tenant_id,id,'customer' FROM drm.users;
INSERT INTO drm.user_roles(tenant_id,user_id,role)
  SELECT DISTINCT tenant_id,owner_user_id,'creator' FROM drm.assets;
ALTER TABLE drm.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.user_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.user_roles
  USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
