-- Run after migrations as the schema owner. Login credentials are provisioned
-- separately; runtime logins receive exactly one of these NOLOGIN roles.
BEGIN;
DO $$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['drm_runtime_api', 'drm_runtime_worker'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', role_name);
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name AND
      (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
      RAISE EXCEPTION 'Unsafe existing runtime role: %', role_name;
    END IF;
  END LOOP;
END;
$$;
GRANT USAGE ON SCHEMA drm TO drm_runtime_api, drm_runtime_worker;
GRANT SELECT ON drm.tenants, drm.users, drm.devices, drm.assets, drm.asset_versions,
  drm.policies, drm.entitlements, drm.rendition_keys, drm.asset_packages, drm.licenses,
  drm.device_activations, drm.device_challenges, drm.device_enrollment_challenges,
  drm.api_rate_windows, drm.publication_operations TO drm_runtime_api;
GRANT SELECT, INSERT, DELETE ON drm.package_objects TO drm_runtime_api;
GRANT INSERT ON drm.devices, drm.assets, drm.asset_versions, drm.policies,
  drm.rendition_keys, drm.asset_packages, drm.licenses, drm.device_activations,
  drm.device_challenges, drm.device_enrollment_challenges, drm.api_rate_windows,
  drm.publication_operations, drm.audit_events, drm.outbox_events TO drm_runtime_api;
-- PostgreSQL status row locks require an UPDATE privilege.
GRANT UPDATE (status) ON drm.users, drm.assets, drm.entitlements, drm.rendition_keys TO drm_runtime_api;
GRANT UPDATE (revoked_at) ON drm.devices, drm.licenses TO drm_runtime_api;
GRANT UPDATE (released_at) ON drm.device_activations TO drm_runtime_api;
GRANT UPDATE (consumed_at) ON drm.device_challenges, drm.device_enrollment_challenges TO drm_runtime_api;
GRANT UPDATE (request_count) ON drm.api_rate_windows TO drm_runtime_api;
GRANT UPDATE (status, encrypted_package, updated_at) ON drm.publication_operations TO drm_runtime_api;

GRANT SELECT ON drm.tenants, drm.outbox_events, drm.api_rate_windows,
  drm.device_challenges, drm.device_enrollment_challenges TO drm_runtime_worker;
GRANT UPDATE ON drm.outbox_events TO drm_runtime_worker;
GRANT DELETE ON drm.api_rate_windows, drm.device_challenges, drm.device_enrollment_challenges TO drm_runtime_worker;
GRANT INSERT ON drm.audit_events TO drm_runtime_worker;
COMMIT;
