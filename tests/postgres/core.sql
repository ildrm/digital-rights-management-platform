BEGIN;

CREATE ROLE drm_test_app NOLOGIN;
GRANT USAGE ON SCHEMA drm TO drm_test_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA drm TO drm_test_app;
SET ROLE drm_test_app;

SET app.tenant_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
INSERT INTO drm.tenants (id, slug) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'tenant-a');
INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111', 'idp:user-1', 'active');
INSERT INTO drm.assets (tenant_id, id, owner_user_id, status) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'draft');
INSERT INTO drm.policies (tenant_id, id, version, asset_id, document, digest) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '33333333-3333-4333-8333-333333333333', 1, '22222222-2222-4222-8222-222222222222', '{}', decode(repeat('ab', 32), 'hex'));

SET app.tenant_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
INSERT INTO drm.tenants (id, slug) VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'tenant-b');

DO $$
BEGIN
  IF (SELECT count(*) FROM drm.tenants) <> 1 THEN RAISE EXCEPTION 'tenant row isolation failed'; END IF;
  IF (SELECT count(*) FROM drm.users) <> 0 THEN RAISE EXCEPTION 'user row isolation failed'; END IF;
  IF (SELECT count(*) FROM drm.policies) <> 0 THEN RAISE EXCEPTION 'policy row isolation failed'; END IF;
  BEGIN
    INSERT INTO drm.users (tenant_id, id, external_subject, status) VALUES
      ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '44444444-4444-4444-8444-444444444444', 'cross-tenant', 'active');
    RAISE EXCEPTION 'cross-tenant write succeeded';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END;
$$;

SET app.tenant_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
DO $$
BEGIN
  BEGIN
    UPDATE drm.policies SET document = '{"forged":true}' WHERE id = '33333333-3333-4333-8333-333333333333';
    RAISE EXCEPTION 'policy mutation succeeded';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'policy mutation succeeded' THEN RAISE; END IF;
  END;
END;
$$;

RESET ROLE;
ROLLBACK;
