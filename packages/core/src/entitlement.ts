import type { Action, Device, Entitlement, Policy, Principal } from './model.ts';
import { validatePolicy } from './policy.ts';

export interface DecisionContext {
  readonly now: string;
  readonly territory: string;
  readonly online: boolean;
  readonly organizationId?: string;
  readonly roles: readonly string[];
  readonly activeDeviceCount: number;
  readonly activeSessionCount: number;
  readonly useCount: number;
  readonly exportCount: number;
  readonly creditsUsed: number;
  readonly fulfilledDuties: readonly string[];
}

export interface AccessRequest {
  readonly principal: Principal;
  readonly device: Device;
  readonly entitlement: Entitlement;
  readonly policy: Policy;
  readonly assetVersion: string;
  readonly action: Action;
  readonly context: DecisionContext;
}

export interface AccessDecision {
  readonly allowed: boolean;
  readonly reasons: readonly string[];
  readonly policyVersion: number;
}

function validInstant(value: string): number | undefined {
  const result = Date.parse(value);
  return Number.isFinite(result) && new Date(result).toISOString() === value ? result : undefined;
}

export function evaluateAccess(request: AccessRequest): AccessDecision {
  const { principal, device, entitlement, policy, assetVersion, action, context } = request;
  validatePolicy(policy);
  const reasons: string[] = [];
  const now = validInstant(context.now);
  if (now === undefined) reasons.push('invalid trusted time');
  if (principal.tenantId !== policy.tenantId || entitlement.tenantId !== policy.tenantId || device.tenantId !== policy.tenantId || entitlement.subject.tenantId !== policy.tenantId) reasons.push('tenant mismatch');
  if (entitlement.assetId !== policy.assetId || entitlement.policyId !== policy.id || entitlement.policyVersion !== policy.version || entitlement.assetVersion !== assetVersion) reasons.push('entitlement does not match asset or policy version');
  if (policy.constraints.assetVersion !== undefined && policy.constraints.assetVersion !== assetVersion) reasons.push('asset version constraint');
  if (entitlement.status !== 'active') reasons.push('entitlement inactive');
  if (entitlement.subject.kind !== principal.kind || entitlement.subject.id !== principal.id) reasons.push('subject mismatch');
  if (device.userId !== principal.id || principal.kind !== 'user') reasons.push('device owner mismatch');
  if (device.revokedAt !== undefined) reasons.push('device revoked');
  if (!policy.permissions.includes(action) || policy.prohibitions.includes(action)) reasons.push('action not permitted');
  const start = validInstant(entitlement.validFrom);
  if (start === undefined || (now !== undefined && now < start)) reasons.push('entitlement not yet valid');
  if (entitlement.validUntil !== undefined) {
    const end = validInstant(entitlement.validUntil);
    if (end === undefined || (now !== undefined && now >= end)) reasons.push('entitlement expired');
  }
  if (policy.constraints.notBefore !== undefined) {
    const startPolicy = validInstant(policy.constraints.notBefore);
    if (startPolicy === undefined || (now !== undefined && now < startPolicy)) reasons.push('policy not yet valid');
  }
  if (policy.constraints.expiresAt !== undefined) {
    const endPolicy = validInstant(policy.constraints.expiresAt);
    if (endPolicy === undefined || (now !== undefined && now >= endPolicy)) reasons.push('policy expired');
  }
  if (policy.constraints.territories !== undefined && !policy.constraints.territories.includes(context.territory)) reasons.push('territory restricted');
  if (policy.constraints.deviceClasses !== undefined && !policy.constraints.deviceClasses.includes(device.deviceClass)) reasons.push('device class restricted');
  if (policy.constraints.minimumDeviceTrust === 'hardware' && device.trust !== 'hardware') reasons.push('hardware trust required');
  if (policy.constraints.onlineOnly && !context.online) reasons.push('online access required');
  if (policy.constraints.maxDevices !== undefined && (!Number.isSafeInteger(context.activeDeviceCount) || context.activeDeviceCount >= policy.constraints.maxDevices)) reasons.push('device limit reached');
  if (policy.constraints.maxConcurrentSessions !== undefined && (!Number.isSafeInteger(context.activeSessionCount) || context.activeSessionCount >= policy.constraints.maxConcurrentSessions)) reasons.push('session limit reached');
  if (policy.constraints.maxUses !== undefined && (!Number.isSafeInteger(context.useCount) || context.useCount >= policy.constraints.maxUses)) reasons.push('use limit reached');
  if (policy.constraints.maxExports !== undefined && action === 'export' && (!Number.isSafeInteger(context.exportCount) || context.exportCount >= policy.constraints.maxExports)) reasons.push('export limit reached');
  if (policy.constraints.creditLimit !== undefined && (!Number.isSafeInteger(context.creditsUsed) || context.creditsUsed >= policy.constraints.creditLimit)) reasons.push('credit limit reached');
  if (policy.constraints.organizationId !== undefined && context.organizationId !== policy.constraints.organizationId) reasons.push('organization restricted');
  if (policy.constraints.requiredRole !== undefined && !context.roles.includes(policy.constraints.requiredRole)) reasons.push('role required');
  for (const duty of policy.duties) if (!context.fulfilledDuties.includes(`${duty.type}:${duty.reference}`)) reasons.push(`duty unfulfilled: ${duty.type}`);
  return { allowed: reasons.length === 0, reasons, policyVersion: policy.version };
}
