BEGIN;

ALTER TABLE drm.outbox_events
  ADD COLUMN dead_lettered_at timestamptz,
  ADD COLUMN last_error_code text CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
  ADD CONSTRAINT outbox_one_terminal_state CHECK (delivered_at IS NULL OR dead_lettered_at IS NULL);

DROP INDEX drm.outbox_ready;
CREATE INDEX outbox_ready ON drm.outbox_events (tenant_id, available_at, created_at)
  WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;

COMMIT;
