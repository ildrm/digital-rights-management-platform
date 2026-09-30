import { createHash } from 'node:crypto';
import { ACTIONS, type Action, type Constraints, type Policy, type Target } from './model.ts';
import { DomainError, requireValue } from './errors.ts';
import { canonicalJson } from './canonical.ts';

type ConstraintKey = keyof Constraints;
const constraintKeys: readonly ConstraintKey[] = [
  'notBefore', 'expiresAt', 'maxDevices', 'maxConcurrentSessions', 'maxUses',
  'maxExports', 'territories', 'deviceClasses', 'minimumDeviceTrust',
  'onlineOnly', 'offlineSeconds', 'organizationId', 'requiredRole',
  'assetVersion', 'feature', 'creditLimit',
];

const capabilities: Record<Target, { actions: readonly Action[]; constraints: readonly ConstraintKey[] }> = {
  secureViewer: {
    actions: ['view', 'read', 'play', 'listen', 'downloadProtected', 'print', 'copy', 'quote', 'annotate'],
    constraints: ['notBefore', 'expiresAt', 'maxDevices', 'maxConcurrentSessions', 'maxUses', 'territories', 'deviceClasses', 'minimumDeviceTrust', 'onlineOnly', 'offlineSeconds', 'organizationId', 'requiredRole', 'assetVersion'],
  },
  publication: {
    actions: ['view', 'read', 'listen', 'downloadProtected', 'print', 'copy', 'quote', 'annotate'],
    constraints: ['notBefore', 'expiresAt', 'maxDevices', 'maxConcurrentSessions', 'maxUses', 'territories', 'deviceClasses', 'minimumDeviceTrust', 'onlineOnly', 'offlineSeconds', 'organizationId', 'requiredRole', 'assetVersion'],
  },
  software: {
    actions: ['execute', 'install', 'downloadProtected', 'apiAccess', 'query', 'infer'],
    constraints: constraintKeys,
  },
  remoteExecution: {
    actions: ['view', 'read', 'play', 'listen', 'execute', 'stream', 'print', 'copy', 'quote', 'annotate', 'modify', 'apiAccess', 'query', 'infer'],
    constraints: constraintKeys.filter((key) => key !== 'offlineSeconds'),
  },
  widevine: {
    actions: ['play', 'listen', 'stream', 'downloadProtected'],
    constraints: ['notBefore', 'expiresAt', 'maxDevices', 'maxConcurrentSessions', 'territories', 'deviceClasses', 'minimumDeviceTrust', 'onlineOnly', 'offlineSeconds', 'assetVersion'],
  },
  fairplay: {
    actions: ['play', 'listen', 'stream', 'downloadProtected'],
    constraints: ['notBefore', 'expiresAt', 'maxDevices', 'maxConcurrentSessions', 'territories', 'deviceClasses', 'minimumDeviceTrust', 'onlineOnly', 'offlineSeconds', 'assetVersion'],
  },
  playready: {
    actions: ['play', 'listen', 'stream', 'downloadProtected'],
    constraints: ['notBefore', 'expiresAt', 'maxDevices', 'maxConcurrentSessions', 'territories', 'deviceClasses', 'minimumDeviceTrust', 'onlineOnly', 'offlineSeconds', 'assetVersion'],
  },
};

export interface CompatibilityReport {
  readonly target: Target;
  readonly compatible: boolean;
  readonly unsupportedActions: readonly Action[];
  readonly unsupportedConstraints: readonly ConstraintKey[];
  readonly explanations: readonly string[];
}

export interface CompiledPolicy {
  readonly formatVersion: 2;
  readonly target: Target;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly tenantId: string;
  readonly assetId: string;
  readonly profile: Policy['profile'];
  readonly allowedActions: readonly Action[];
  readonly constraints: Constraints;
  readonly duties: Policy['duties'];
  readonly sourceDigest: string;
}

function timestamp(value: string, name: string): number {
  const result = typeof value === 'string' ? Date.parse(value) : NaN;
  requireValue(Number.isFinite(result) && new Date(result).toISOString() === value, 'INVALID_POLICY', `${name} must be an ISO UTC timestamp`);
  return result;
}

export function validatePolicy(policy: Policy): void {
  requireValue(policy !== null && typeof policy === 'object' && !Array.isArray(policy) &&
    policy.constraints !== null && typeof policy.constraints === 'object' && !Array.isArray(policy.constraints),
  'INVALID_POLICY', 'Policy and constraints required');
  const policyKeys = ['id', 'version', 'tenantId', 'assetId', 'profile', 'permissions', 'prohibitions', 'duties', 'constraints', 'preventOriginalPossession'];
  requireValue(Object.keys(policy).length === policyKeys.length && policyKeys.every((key) => Object.hasOwn(policy, key)), 'INVALID_POLICY', 'Policy fields are incomplete or unknown');
  requireValue([policy.id, policy.tenantId, policy.assetId].every((value) => typeof value === 'string' && value.length > 0 && value.length <= 256), 'INVALID_POLICY', 'Policy identifiers must be 1–256 characters');
  requireValue(Number.isSafeInteger(policy.version) && policy.version > 0, 'INVALID_POLICY', 'Policy version must be positive');
  requireValue(['public', 'controlled', 'protected', 'highSecurity', 'maximum'].includes(policy.profile), 'INVALID_POLICY', 'Unknown protection profile');
  requireValue(typeof policy.preventOriginalPossession === 'boolean', 'INVALID_POLICY', 'Original possession flag required');
  requireValue(Array.isArray(policy.permissions) && Array.isArray(policy.prohibitions) && Array.isArray(policy.duties), 'INVALID_POLICY', 'Rules must be arrays');
  const permissions = new Set(policy.permissions);
  const prohibitions = new Set(policy.prohibitions);
  requireValue(permissions.size === policy.permissions.length && prohibitions.size === policy.prohibitions.length, 'INVALID_POLICY', 'Duplicate actions');
  for (const action of [...permissions, ...prohibitions]) requireValue(ACTIONS.includes(action), 'INVALID_POLICY', `Unknown action: ${action}`);
  for (const action of permissions) requireValue(!prohibitions.has(action), 'POLICY_CONTRADICTION', `${action} is both permitted and prohibited`);
  requireValue(!(permissions.has('downloadOriginal') && policy.preventOriginalPossession), 'POLICY_CONTRADICTION', 'Original download conflicts with original-possession restriction');
  requireValue(!(policy.profile === 'maximum' && (permissions.has('downloadOriginal') || permissions.has('downloadProtected'))), 'POLICY_CONTRADICTION', 'Maximum protection does not deliver asset packages');
  requireValue(!(policy.constraints.onlineOnly && policy.constraints.offlineSeconds !== undefined), 'POLICY_CONTRADICTION', 'Online-only conflicts with offline access');
  for (const key of Object.keys(policy.constraints)) requireValue(constraintKeys.includes(key as ConstraintKey), 'INVALID_POLICY', `Unknown constraint: ${key}`);
  if (policy.constraints.notBefore !== undefined && policy.constraints.expiresAt !== undefined) {
    requireValue(timestamp(policy.constraints.notBefore, 'notBefore') < timestamp(policy.constraints.expiresAt, 'expiresAt'), 'POLICY_CONTRADICTION', 'Validity window is empty');
  } else {
    if (policy.constraints.notBefore !== undefined) timestamp(policy.constraints.notBefore, 'notBefore');
    if (policy.constraints.expiresAt !== undefined) timestamp(policy.constraints.expiresAt, 'expiresAt');
  }
  for (const key of ['maxDevices', 'maxConcurrentSessions', 'maxUses', 'maxExports', 'offlineSeconds', 'creditLimit'] as const) {
    const value = policy.constraints[key];
    if (value !== undefined) requireValue(Number.isSafeInteger(value) && value > 0, 'INVALID_POLICY', `${key} must be a positive safe integer`);
  }
  if (policy.constraints.territories !== undefined) requireValue(Array.isArray(policy.constraints.territories) && policy.constraints.territories.length > 0 && policy.constraints.territories.length <= 249 && policy.constraints.territories.every((x) => typeof x === 'string' && /^[A-Z]{2}$/.test(x)) && new Set(policy.constraints.territories).size === policy.constraints.territories.length, 'INVALID_POLICY', 'Territories must be distinct two-letter uppercase codes');
  if (policy.constraints.deviceClasses !== undefined) requireValue(Array.isArray(policy.constraints.deviceClasses) && policy.constraints.deviceClasses.length > 0 && policy.constraints.deviceClasses.length <= 32 && policy.constraints.deviceClasses.every((x) => typeof x === 'string' && /^[a-z][a-z0-9-]{0,31}$/.test(x)) && new Set(policy.constraints.deviceClasses).size === policy.constraints.deviceClasses.length, 'INVALID_POLICY', 'Device classes must be distinct short identifiers');
  if (policy.constraints.minimumDeviceTrust !== undefined) requireValue(['software', 'hardware'].includes(policy.constraints.minimumDeviceTrust), 'INVALID_POLICY', 'Unknown device trust');
  if (policy.constraints.onlineOnly !== undefined) requireValue(typeof policy.constraints.onlineOnly === 'boolean', 'INVALID_POLICY', 'onlineOnly must be boolean');
  for (const key of ['organizationId', 'requiredRole', 'assetVersion', 'feature'] as const) {
    const value = policy.constraints[key];
    if (value !== undefined) requireValue(typeof value === 'string' && value.length > 0 && value.length <= 256, 'INVALID_POLICY', `${key} must be a short nonempty string`);
  }
  requireValue(policy.duties.length <= 32, 'INVALID_POLICY', 'Too many duties');
  for (const duty of policy.duties) requireValue(duty !== null && typeof duty === 'object' && !Array.isArray(duty) &&
    Object.keys(duty).length === 2 && Object.hasOwn(duty, 'type') && Object.hasOwn(duty, 'reference') &&
    ['payment', 'attribution', 'acknowledgement', 'return', 'reporting'].includes(duty.type) &&
    typeof duty.reference === 'string' && duty.reference.length > 0 && duty.reference.length <= 256,
  'INVALID_POLICY', 'Invalid duty');
}

export function analyzeCompatibility(policy: Policy, target: Target): CompatibilityReport {
  validatePolicy(policy);
  requireValue(typeof target === 'string' && Object.hasOwn(capabilities, target), 'INVALID_TARGET', 'Unknown enforcement target');
  const support = capabilities[target];
  const allowed = policy.permissions.filter((action) => !policy.prohibitions.includes(action));
  const unsupportedActions = allowed.filter((action) => !support.actions.includes(action));
  const unsupportedConstraints = (Object.keys(policy.constraints) as ConstraintKey[]).filter((key) => !support.constraints.includes(key));
  const explanations = [
    ...unsupportedActions.map((action) => `${target} cannot enforce action ${action}`),
    ...unsupportedConstraints.map((key) => `${target} cannot enforce constraint ${key}`),
  ];
  if (target !== 'secureViewer') explanations.push(`${target} enforcement adapter and certification are not installed`);
  if (policy.profile === 'maximum' && target !== 'remoteExecution') explanations.push('Maximum protection requires remote execution');
  if (policy.profile === 'highSecurity' && policy.constraints.minimumDeviceTrust !== 'hardware') explanations.push('High security requires hardware device trust');
  return { target, compatible: explanations.length === 0, unsupportedActions, unsupportedConstraints, explanations };
}

export function compilePolicy(policy: Policy, target: Target): CompiledPolicy {
  const report = analyzeCompatibility(policy, target);
  if (!report.compatible) throw new DomainError('UNSUPPORTED_POLICY', report.explanations.join('; '));
  const allowedActions = [...policy.permissions].sort();
  const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
  const constraints = Object.fromEntries(Object.entries(structuredClone(policy.constraints)).sort(([a], [b]) => compare(a, b))) as Constraints;
  const duties = policy.duties.map((duty) => ({ ...duty })).sort((a, b) => compare(`${a.type}:${a.reference}`, `${b.type}:${b.reference}`));
  const canonical = canonicalJson({
    id: policy.id, version: policy.version, tenantId: policy.tenantId, assetId: policy.assetId,
    profile: policy.profile, allowedActions, prohibitions: [...policy.prohibitions].sort(),
    constraints, duties, preventOriginalPossession: policy.preventOriginalPossession,
  });
  return {
    formatVersion: 2, target, policyId: policy.id, policyVersion: policy.version,
    tenantId: policy.tenantId, assetId: policy.assetId, profile: policy.profile,
    allowedActions, constraints, duties, sourceDigest: createHash('sha256').update(canonical).digest('hex'),
  };
}
