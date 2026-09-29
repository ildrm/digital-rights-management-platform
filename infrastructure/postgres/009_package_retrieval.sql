BEGIN;

ALTER TABLE drm.licenses ADD COLUMN rendition_id uuid;
CREATE INDEX licenses_package_access ON drm.licenses (tenant_id, id, rendition_id)
  WHERE revoked_at IS NULL;

ALTER TABLE drm.api_rate_windows DROP CONSTRAINT api_rate_windows_operation_check;
ALTER TABLE drm.api_rate_windows ADD CONSTRAINT api_rate_windows_operation_check
  CHECK (operation IN ('device-challenge', 'license-issue', 'asset-publish', 'asset-fetch'));

COMMIT;
