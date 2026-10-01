BEGIN;

CREATE TABLE drm.payment_reconciliation (
  tenant_id uuid NOT NULL,
  order_id uuid NOT NULL,
  due_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '1 minute',
  failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 1000000),
  PRIMARY KEY (tenant_id, order_id),
  FOREIGN KEY (tenant_id, order_id) REFERENCES drm.purchase_orders (tenant_id, id)
);
CREATE INDEX payment_reconciliation_due ON drm.payment_reconciliation (tenant_id, due_at, order_id);
INSERT INTO drm.payment_reconciliation(tenant_id,order_id)
  SELECT tenant_id,id FROM drm.purchase_orders WHERE status = 'pending' AND checkout_session_id IS NOT NULL;
ALTER TABLE drm.payment_reconciliation ENABLE ROW LEVEL SECURITY;
ALTER TABLE drm.payment_reconciliation FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON drm.payment_reconciliation USING (tenant_id = drm.current_tenant()) WITH CHECK (tenant_id = drm.current_tenant());

COMMIT;
