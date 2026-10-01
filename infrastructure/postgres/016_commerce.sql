BEGIN;

CREATE TABLE drm.offers (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  creator_user_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  asset_version integer NOT NULL CHECK (asset_version > 0),
  policy_id uuid NOT NULL,
  policy_version integer NOT NULL CHECK (policy_version > 0),
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
  amount_minor integer NOT NULL CHECK (amount_minor BETWEEN 1 AND 99999999),
  currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, creator_user_id) REFERENCES drm.users (tenant_id, id),
  FOREIGN KEY (tenant_id, asset_id, asset_version) REFERENCES drm.asset_versions (tenant_id, asset_id, version),
  FOREIGN KEY (tenant_id, policy_id, policy_version, asset_id) REFERENCES drm.policies (tenant_id, id, version, asset_id)
);
CREATE INDEX offers_active_page ON drm.offers (tenant_id, id) WHERE status = 'active';

CREATE TABLE drm.purchase_orders (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL UNIQUE,
  buyer_user_id uuid NOT NULL,
  offer_id uuid NOT NULL,
  idempotency_key uuid NOT NULL,
  amount_minor integer NOT NULL CHECK (amount_minor BETWEEN 1 AND 99999999),
  currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'canceled')),
  checkout_session_id text UNIQUE,
  payment_intent_id text UNIQUE,
  entitlement_id uuid,
  paid_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, buyer_user_id, idempotency_key),
  FOREIGN KEY (tenant_id, buyer_user_id) REFERENCES drm.users (tenant_id, id),
  FOREIGN KEY (tenant_id, offer_id) REFERENCES drm.offers (tenant_id, id),
  FOREIGN KEY (tenant_id, entitlement_id) REFERENCES drm.entitlements (tenant_id, id),
  CHECK (checkout_session_id IS NULL OR checkout_session_id ~ '^cs_[A-Za-z0-9_]{8,192}$'),
  CHECK (payment_intent_id IS NULL OR payment_intent_id ~ '^pi_[A-Za-z0-9]{8,128}$'),
  CHECK ((status = 'paid' AND paid_at IS NOT NULL AND entitlement_id IS NOT NULL AND
          checkout_session_id IS NOT NULL AND payment_intent_id IS NOT NULL) OR
         (status <> 'paid' AND paid_at IS NULL AND entitlement_id IS NULL))
);
CREATE INDEX purchase_orders_buyer_page ON drm.purchase_orders (tenant_id, buyer_user_id, id);
CREATE INDEX purchase_orders_pending ON drm.purchase_orders (tenant_id, created_at, id) WHERE status = 'pending';

CREATE TABLE drm.payment_events (
  event_id text PRIMARY KEY CHECK (event_id ~ '^evt_[A-Za-z0-9]{8,128}$'),
  tenant_id uuid NOT NULL,
  order_id uuid NOT NULL,
  session_id text NOT NULL,
  payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
  processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id, order_id) REFERENCES drm.purchase_orders (tenant_id, id)
);

-- Every immutable journal row represents equal debit and credit postings.
-- Provider fees, tax, and payout journals require separate reconciliation.
CREATE TABLE drm.commerce_journal (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  order_id uuid NOT NULL,
  amount_minor integer NOT NULL CHECK (amount_minor BETWEEN 1 AND 99999999),
  currency text NOT NULL CHECK (currency ~ '^[a-z]{3}$'),
  debit_account text NOT NULL CHECK (debit_account = 'processor_receivable'),
  credit_account text NOT NULL CHECK (credit_account = 'creator_payable'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, order_id),
  FOREIGN KEY (tenant_id, order_id) REFERENCES drm.purchase_orders (tenant_id, id)
);

CREATE FUNCTION drm.guard_offer_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - 'status') <> (to_jsonb(OLD) - 'status') THEN
    RAISE EXCEPTION 'immutable offer binding';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER offers_binding BEFORE UPDATE ON drm.offers FOR EACH ROW EXECUTE FUNCTION drm.guard_offer_binding();
CREATE TRIGGER offers_no_delete BEFORE DELETE ON drm.offers FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();

CREATE FUNCTION drm.guard_order_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['status', 'checkout_session_id', 'payment_intent_id', 'entitlement_id', 'paid_at']) <>
     (to_jsonb(OLD) - ARRAY['status', 'checkout_session_id', 'payment_intent_id', 'entitlement_id', 'paid_at']) OR
     (OLD.checkout_session_id IS NOT NULL AND NEW.checkout_session_id IS DISTINCT FROM OLD.checkout_session_id) OR
     (OLD.payment_intent_id IS NOT NULL AND NEW.payment_intent_id IS DISTINCT FROM OLD.payment_intent_id) OR
     (OLD.status = 'paid' AND NEW IS DISTINCT FROM OLD) THEN
    RAISE EXCEPTION 'immutable order binding';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER orders_binding BEFORE UPDATE ON drm.purchase_orders FOR EACH ROW EXECUTE FUNCTION drm.guard_order_binding();
CREATE TRIGGER orders_no_delete BEFORE DELETE ON drm.purchase_orders FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();
CREATE TRIGGER payment_events_immutable BEFORE UPDATE OR DELETE ON drm.payment_events FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();
CREATE TRIGGER commerce_journal_immutable BEFORE UPDATE OR DELETE ON drm.commerce_journal FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();

ALTER TABLE drm.offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.offers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.offers USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
ALTER TABLE drm.purchase_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.purchase_orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.purchase_orders USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
ALTER TABLE drm.payment_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.payment_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.payment_events USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());
ALTER TABLE drm.commerce_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.commerce_journal FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.commerce_journal USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());

ALTER TABLE drm.api_rate_windows DROP CONSTRAINT api_rate_windows_operation_check;
ALTER TABLE drm.api_rate_windows ADD CONSTRAINT api_rate_windows_operation_check
  CHECK (operation IN ('device-challenge', 'license-issue', 'asset-publish', 'asset-fetch', 'commerce-write'));

COMMIT;
