BEGIN;

CREATE INDEX assets_owner_published_page ON drm.assets (tenant_id, owner_user_id, id)
  WHERE status = 'published';
CREATE INDEX entitlements_library_page ON drm.entitlements (tenant_id, subject_user_id, id)
  WHERE status = 'active';

COMMIT;
