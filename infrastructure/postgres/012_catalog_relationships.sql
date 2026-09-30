BEGIN;

-- A grant and a license must remain bound to the same immutable policy and asset.
ALTER TABLE drm.policies ADD CONSTRAINT policies_asset_binding
  UNIQUE (tenant_id, id, version, asset_id);
ALTER TABLE drm.entitlements ADD CONSTRAINT entitlements_policy_binding
  FOREIGN KEY (tenant_id, policy_id, policy_version, asset_id)
  REFERENCES drm.policies (tenant_id, id, version, asset_id) NOT VALID;
ALTER TABLE drm.entitlements VALIDATE CONSTRAINT entitlements_policy_binding;

ALTER TABLE drm.entitlements ADD CONSTRAINT entitlements_license_binding
  UNIQUE (tenant_id, id, policy_id, policy_version);
ALTER TABLE drm.licenses ADD CONSTRAINT licenses_entitlement_policy_binding
  FOREIGN KEY (tenant_id, entitlement_id, policy_id, policy_version)
  REFERENCES drm.entitlements (tenant_id, id, policy_id, policy_version) NOT VALID;
ALTER TABLE drm.licenses VALIDATE CONSTRAINT licenses_entitlement_policy_binding;

CREATE TRIGGER asset_versions_immutable BEFORE UPDATE OR DELETE ON drm.asset_versions
  FOR EACH ROW EXECUTE FUNCTION drm.reject_mutation();

COMMIT;
