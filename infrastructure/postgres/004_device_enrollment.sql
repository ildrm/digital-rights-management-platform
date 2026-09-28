BEGIN;

ALTER TABLE drm.devices
  ADD COLUMN public_key_sha256 bytea CHECK (public_key_sha256 IS NULL OR octet_length(public_key_sha256) = 32);
CREATE UNIQUE INDEX devices_unique_public_key ON drm.devices (tenant_id, public_key_sha256)
  WHERE public_key_sha256 IS NOT NULL;

CREATE TABLE drm.device_enrollment_challenges (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  user_id uuid NOT NULL,
  public_key_sha256 bytea NOT NULL CHECK (octet_length(public_key_sha256) = 32),
  device_class text NOT NULL CHECK (length(device_class) BETWEEN 1 AND 32),
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, challenge_hash),
  FOREIGN KEY (tenant_id, user_id) REFERENCES drm.users (tenant_id, id)
);
CREATE INDEX device_enrollment_challenges_expiry ON drm.device_enrollment_challenges (expires_at);

ALTER TABLE drm.device_enrollment_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.device_enrollment_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.device_enrollment_challenges
  USING (tenant_id = drm.current_tenant())
  WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
