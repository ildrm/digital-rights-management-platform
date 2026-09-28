BEGIN;

CREATE SCHEMA IF NOT EXISTS drm;

CREATE TABLE drm.tenants (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE CHECK (length(slug) BETWEEN 3 AND 80),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE drm.users (
  tenant_id uuid NOT NULL REFERENCES drm.tenants(id),
  id uuid NOT NULL,
  external_subject text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, external_subject)
);

CREATE TABLE drm.devices (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  user_id uuid NOT NULL,
  public_key_pem text NOT NULL,
  trust_level text NOT NULL CHECK (trust_level IN ('software', 'hardware')),
  device_class text NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES drm.users (tenant_id, id)
);

CREATE TABLE drm.assets (
  tenant_id uuid NOT NULL REFERENCES drm.tenants(id),
  id uuid NOT NULL,
  owner_user_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('draft', 'published', 'withdrawn')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES drm.users (tenant_id, id)
);

CREATE TABLE drm.asset_versions (
  tenant_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, asset_id, version),
  FOREIGN KEY (tenant_id, asset_id) REFERENCES drm.assets (tenant_id, id)
);

CREATE TABLE drm.policies (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  asset_id uuid NOT NULL,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id, version),
  FOREIGN KEY (tenant_id, asset_id) REFERENCES drm.assets (tenant_id, id)
);

CREATE TABLE drm.entitlements (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  subject_user_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  asset_version integer NOT NULL,
  policy_id uuid NOT NULL,
  policy_version integer NOT NULL,
  source text NOT NULL CHECK (source IN ('purchase', 'rental', 'subscription', 'organization', 'free', 'trial', 'lending')),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  FOREIGN KEY (tenant_id, subject_user_id) REFERENCES drm.users (tenant_id, id),
  FOREIGN KEY (tenant_id, asset_id, asset_version) REFERENCES drm.asset_versions (tenant_id, asset_id, version),
  FOREIGN KEY (tenant_id, policy_id, policy_version) REFERENCES drm.policies (tenant_id, id, version)
);
CREATE INDEX entitlements_subject_active ON drm.entitlements (tenant_id, subject_user_id, asset_id) WHERE status = 'active';

CREATE TABLE drm.device_challenges (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  device_id uuid NOT NULL,
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, challenge_hash),
  FOREIGN KEY (tenant_id, device_id) REFERENCES drm.devices (tenant_id, id)
);
CREATE INDEX device_challenges_expiry ON drm.device_challenges (expires_at);

CREATE TABLE drm.licenses (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  entitlement_id uuid NOT NULL,
  device_id uuid NOT NULL,
  policy_id uuid NOT NULL,
  policy_version integer NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  claims_sha256 bytea NOT NULL CHECK (octet_length(claims_sha256) = 32),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  CHECK (expires_at > issued_at),
  FOREIGN KEY (tenant_id, entitlement_id) REFERENCES drm.entitlements (tenant_id, id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES drm.devices (tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id, policy_version) REFERENCES drm.policies (tenant_id, id, version)
);
CREATE INDEX licenses_device_live ON drm.licenses (tenant_id, device_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE drm.audit_events (
  tenant_id uuid NOT NULL REFERENCES drm.tenants(id),
  id uuid NOT NULL,
  actor_id uuid,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  details jsonb NOT NULL CHECK (jsonb_typeof(details) = 'object'),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX audit_events_timeline ON drm.audit_events (tenant_id, occurred_at DESC);

CREATE FUNCTION drm.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'immutable record';
END;
$$;
CREATE TRIGGER policies_immutable BEFORE UPDATE OR DELETE ON drm.policies FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON drm.audit_events FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();

CREATE FUNCTION drm.current_tenant() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

ALTER TABLE drm.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.asset_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.device_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.audit_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE drm.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.users FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.devices FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.assets FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.asset_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.policies FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.device_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.licenses FORCE ROW LEVEL SECURITY;
ALTER TABLE drm.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON drm.tenants USING (id = drm.current_tenant()) WITH CHECK (id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.users USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.devices USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.assets USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.asset_versions USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.policies USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.entitlements USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.device_challenges USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.licenses USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
CREATE POLICY tenant_isolation ON drm.audit_events USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
