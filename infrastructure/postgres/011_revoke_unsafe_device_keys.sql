BEGIN;

-- Legacy enrollments could have stored private PEMs. Remove the stored value,
-- revoke access, and preserve only device identifiers in the audit trail.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'Unsafe-key cleanup requires a migration role with BYPASSRLS';
  END IF;
END;
$$;

CREATE TEMP TABLE unsafe_device_keys ON COMMIT DROP AS
  SELECT tenant_id, id, user_id FROM drm.devices
  WHERE public_key_pem NOT LIKE '-----BEGIN PUBLIC KEY-----%'
     OR public_key_pem LIKE '%PRIVATE KEY%'
     OR public_key_pem LIKE '%-----BEGIN%-----BEGIN%';

UPDATE drm.devices d SET public_key_pem = 'REVOKED_UNSAFE_KEY',
  revoked_at = COALESCE(revoked_at, clock_timestamp())
FROM unsafe_device_keys u WHERE d.tenant_id = u.tenant_id AND d.id = u.id;

UPDATE drm.licenses l SET revoked_at = COALESCE(revoked_at, clock_timestamp())
FROM unsafe_device_keys u WHERE l.tenant_id = u.tenant_id AND l.device_id = u.id;

DELETE FROM drm.device_challenges c USING unsafe_device_keys u
WHERE c.tenant_id = u.tenant_id AND c.device_id = u.id;

INSERT INTO drm.audit_events (tenant_id, id, event_type, details)
SELECT tenant_id, gen_random_uuid(), 'device.unsafe_key_revoked',
  jsonb_build_object('deviceId', id, 'userId', user_id)
FROM unsafe_device_keys;

COMMIT;
