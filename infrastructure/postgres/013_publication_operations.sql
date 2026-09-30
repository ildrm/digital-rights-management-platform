BEGIN;

CREATE TABLE drm.publication_operations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  owner_user_id uuid NOT NULL,
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'committed', 'abandoned')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  -- Preserve wire key order: the S3 digest covers JSON.stringify(package).
  encrypted_package json,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES drm.users (tenant_id, id),
  CHECK ((status = 'pending') = (encrypted_package IS NOT NULL))
);
CREATE INDEX publication_operations_pending ON drm.publication_operations (tenant_id, updated_at, id)
  WHERE status = 'pending';
CREATE UNIQUE INDEX publication_operation_object ON drm.publication_operations ((document->'asset'->>'objectKey'));
CREATE INDEX publication_operations_cleanup ON drm.publication_operations (tenant_id, updated_at, id)
  WHERE status = 'abandoned';
ALTER TABLE drm.publication_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.publication_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.publication_operations
  USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());

CREATE FUNCTION drm.guard_publication_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.id <> OLD.id OR NEW.owner_user_id <> OLD.owner_user_id
    OR NEW.request_sha256 <> OLD.request_sha256 OR NEW.document <> OLD.document
    OR NEW.created_at <> OLD.created_at
    OR (OLD.status <> 'pending' AND NEW.status <> OLD.status)
    OR (NEW.status = 'pending' AND NEW.encrypted_package::text IS DISTINCT FROM OLD.encrypted_package::text) THEN
    RAISE EXCEPTION 'immutable publication binding';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER publication_operation_binding BEFORE UPDATE ON drm.publication_operations
  FOR EACH ROW EXECUTE FUNCTION drm.guard_publication_operation();

COMMIT;
