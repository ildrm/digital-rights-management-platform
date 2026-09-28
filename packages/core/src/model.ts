export const ACTIONS = [
  'view', 'read', 'play', 'listen', 'execute', 'install', 'stream',
  'downloadProtected', 'downloadOriginal', 'print', 'copy', 'quote',
  'annotate', 'modify', 'export', 'embed', 'share', 'lend', 'transfer',
  'commercialUse', 'derive', 'apiAccess', 'query', 'infer',
] as const;
export type Action = typeof ACTIONS[number];

export type PrincipalKind = 'user' | 'device' | 'household' | 'organization' | 'team' | 'role' | 'serviceAccount' | 'apiClient';
export type ProtectionProfile = 'public' | 'controlled' | 'protected' | 'highSecurity' | 'maximum';
export type Target = 'secureViewer' | 'publication' | 'software' | 'remoteExecution' | 'widevine' | 'fairplay' | 'playready';

export interface Principal {
  readonly kind: PrincipalKind;
  readonly id: string;
  readonly tenantId: string;
}

export interface Constraints {
  readonly notBefore?: string;
  readonly expiresAt?: string;
  readonly maxDevices?: number;
  readonly maxConcurrentSessions?: number;
  readonly maxUses?: number;
  readonly maxExports?: number;
  readonly territories?: readonly string[];
  readonly deviceClasses?: readonly string[];
  readonly minimumDeviceTrust?: 'software' | 'hardware';
  readonly onlineOnly?: boolean;
  readonly offlineSeconds?: number;
  readonly organizationId?: string;
  readonly requiredRole?: string;
  readonly assetVersion?: string;
  readonly feature?: string;
  readonly creditLimit?: number;
}

export interface Duty {
  readonly type: 'payment' | 'attribution' | 'acknowledgement' | 'return' | 'reporting';
  readonly reference: string;
}

export interface Policy {
  readonly id: string;
  readonly version: number;
  readonly tenantId: string;
  readonly assetId: string;
  readonly profile: ProtectionProfile;
  readonly permissions: readonly Action[];
  readonly prohibitions: readonly Action[];
  readonly duties: readonly Duty[];
  readonly constraints: Constraints;
  readonly preventOriginalPossession: boolean;
}

export interface Device {
  readonly id: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly publicKeyPem: string;
  readonly trust: 'software' | 'hardware';
  readonly deviceClass: string;
  readonly revokedAt?: string;
}

export interface Entitlement {
  readonly id: string;
  readonly tenantId: string;
  readonly subject: Principal;
  readonly assetId: string;
  readonly assetVersion: string;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly source: 'purchase' | 'rental' | 'subscription' | 'organization' | 'free' | 'trial' | 'lending';
  readonly status: 'active' | 'revoked' | 'suspended';
  readonly validFrom: string;
  readonly validUntil?: string;
}
