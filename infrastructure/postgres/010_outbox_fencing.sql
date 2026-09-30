BEGIN;

ALTER TABLE drm.outbox_events ADD COLUMN claim_token uuid;
UPDATE drm.outbox_events SET claim_token = gen_random_uuid() WHERE claimed_by IS NOT NULL;
ALTER TABLE drm.outbox_events ADD CONSTRAINT outbox_claim_token_consistent
  CHECK ((claimed_by IS NULL) = (claim_token IS NULL));

COMMIT;
