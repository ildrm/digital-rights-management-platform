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
  readonly formatVersion: 1;
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
  const result = Date.parse(value);
  requireValue(Number.isFinite(result) && new Date(result).toISOString() === value, 'INVALID_POLICY', `${name} must be an ISO UTC timestamp`);
  return result;
}

export function validatePolicy(policy: Policy): void {
  requireValue(policy !== null && typeof policy === 'object' && policy.constraints !== null && typeof policy.constraints === 'object', 'INVALID_POLICY', 'Policy and constraints required');
  const policyKeys = ['id', 'version', 'tenantId', 'assetId', 'profile', 'permissions', 'prohibitions', 'duties', 'constraints', 'preventOriginalPossession'];
  for (const key of Object.keys(policy)) requireValue(policyKeys.includes(key), 'INVALID_POLICY', `Unknown policy field: ${key}`);
  requireValue(typeof policy.id === 'string' && policy.id.length > 0 && typeof policy.tenantId === 'string' && policy.tenantId.length > 0 && typeof policy.assetId === 'string' && policy.assetId.length > 0, 'INVALID_POLICY', 'Policy identifiers are required');
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
  if (policy.constraints.territories !== undefined) requireValue(policy.constraints.territories.length > 0 && policy.constraints.territories.every((x) => /^[A-Z]{2}$/.test(x)), 'INVALID_POLICY', 'Territories must be ISO 3166-1 alpha-2 codes');
  if (policy.constraints.deviceClasses !== undefined) requireValue(policy.constraints.deviceClasses.length > 0 && policy.constraints.deviceClasses.every(Boolean), 'INVALID_POLICY', 'Device classes cannot be empty');
  if (policy.constraints.minimumDeviceTrust !== undefined) requireValue(['software', 'hardware'].includes(policy.constraints.minimumDeviceTrust), 'INVALID_POLICY', 'Unknown device trust');
  for (const duty of policy.duties) requireValue(duty !== null && typeof duty === 'object' && ['payment', 'attribution', 'acknowledgement', 'return', 'reporting'].includes(duty.type) && typeof duty.reference === 'string' && duty.reference.length > 0, 'INVALID_POLICY', 'Invalid duty');
}

export function analyzeCompatibility(policy: Policy, target: Target): CompatibilityReport {
  validatePolicy(policy);
  const support = capabilities[target];
  requireValue(support, 'INVALID_TARGET', 'Unknown enforcement target');
  const allowed = policy.permissions.filter((action) => !policy.prohibitions.includes(action));
  const unsupportedActions = allowed.filter((action) => !support.actions.includes(action));
  const unsupportedConstraints = (Object.keys(policy.constraints) as ConstraintKey[]).filter((key) => !support.constraints.includes(key));
  const explanations = [
    ...unsupportedActions.map((action) => `${target} cannot enforce action ${action}`),
    ...unsupportedConstraints.map((key) => `${target} cannot enforce constraint ${key}`),
  ];
  if (target === 'widevine' || target === 'fairplay' || target === 'playready') explanations.push(`${target} provider adapter and certification are not installed`);
  if (policy.profile === 'maximum' && target !== 'remoteExecution') explanations.push('Maximum protection requires remote execution');
  if (policy.profile === 'highSecurity' && policy.constraints.minimumDeviceTrust !== 'hardware') explanations.push('High security requires hardware device trust');
  return { target, compatible: explanations.length === 0, unsupportedActions, unsupportedConstraints, explanations };
}

export function compilePolicy(policy: Policy, target: Target): CompiledPolicy {
  const report = analyzeCompatibility(policy, target);
  if (!report.compatible) throw new DomainError('UNSUPPORTED_POLICY', report.explanations.join('; '));
  const allowedActions = [...policy.permissions].sort();
  const constraints = Object.fromEntries(Object.entries(policy.constraints).sort(([a], [b]) => a.localeCompare(b))) as Constraints;
  const duties = [...policy.duties].sort((a, b) => `${a.type}:${a.reference}`.localeCompare(`${b.type}:${b.reference}`));
  const canonical = canonicalJson({
    id: policy.id, version: policy.version, tenantId: policy.tenantId, assetId: policy.assetId,
    profile: policy.profile, allowedActions, prohibitions: [...policy.prohibitions].sort(),
    constraints, duties, preventOriginalPossession: policy.preventOriginalPossession,
  });
  return {
    formatVersion: 1, target, policyId: policy.id, policyVersion: policy.version,
    tenantId: policy.tenantId, assetId: policy.assetId, profile: policy.profile,
    allowedActions, constraints, duties, sourceDigest: createHash('sha256').update(canonical).digest('hex'),
  };
}
