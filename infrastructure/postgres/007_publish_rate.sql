BEGIN;

ALTER TABLE drm.api_rate_windows DROP CONSTRAINT api_rate_windows_operation_check;
ALTER TABLE drm.api_rate_windows ADD CONSTRAINT api_rate_windows_operation_check
  CHECK (operation IN ('device-challenge', 'license-issue', 'asset-publish'));

COMMIT;
