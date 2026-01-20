// RBAC TypeScript types mirroring backend models

export type Claim = 'reader' | 'writer' | 'deployer' | 'admin' | 'upgrade';

export type MembershipSource = 'admin' | 'zk_attested';

export interface Organization {
  id: string;
  slug: string;
  name: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Group {
  id: string;
  org_id: string;
  parent_id?: string | null;
  slug: string;
  name: string;
  description?: string;
  depth: number;
  path: string; // Materialized path (e.g., "root.engineering.devops")
  created_at: string;
  updated_at: string;
}

export interface Role {
  id: string;
  org_id: string;
  name: string;
  description?: string;
  claims: Claim[];
  created_at: string;
  updated_at: string;
}

export interface GroupPermissions {
  id: string;
  group_id: string;
  allow_methods: string[];
  allow_contracts: string[];
  owned_contracts: string[];
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  external_id: string; // User's DID
  kyc: boolean;
  banned: boolean;
  note?: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface UserMembership {
  id: string;
  user_id: string;
  group_id: string;
  role_id?: string | null;
  source: MembershipSource;
  zk_credential_ref?: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ContractOwnership {
  id: string;
  contract_address: string;
  org_id: string;
  owner_group_id: string;
  owner_abilities: string[]; // e.g., ["upgrade", "pause", "admin"]
  deployed_by_user_id?: string | null;
  deployed_at?: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface EffectivePermissions {
  id: string;
  user_id: string;
  org_id: string;
  allow_methods: string[];
  allow_contracts: string[];
  owned_contracts: string[];
  claims: Claim[];
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
  computed_at: string;
  expires_at: string;
}

export interface MembershipWithDetails {
  membership: UserMembership;
  group: Group;
  role?: Role | null;
}

export interface AccessCheckRequest {
  user_external_id: string;
  org_slug?: string;
  method: string;
  contract_address?: string;
  required_claims?: Claim[];
}

export interface AccessCheckResult {
  allowed: boolean;
  reason?: string;
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
  claims?: Claim[];
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
}

// Input types for creating/updating entities
export interface CreateOrganizationInput {
  slug: string;
  name: string;
  settings?: Record<string, unknown>;
}

export interface UpdateOrganizationInput {
  slug?: string;
  name?: string;
  settings?: Record<string, unknown>;
}

export interface CreateGroupInput {
  slug: string;
  name: string;
  description?: string;
  parent_id?: string | null;
}

export interface UpdateGroupInput {
  name?: string;
  description?: string;
}

export interface CreateRoleInput {
  name: string;
  description?: string;
  claims?: Claim[];
}

export interface UpdateRoleInput {
  name?: string;
  description?: string;
  claims?: Claim[];
}

export interface UpdateUserInput {
  kyc?: boolean;
  banned?: boolean;
  note?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateMembershipInput {
  group_id: string;
  role_id?: string | null;
}

export interface SetGroupPermissionsInput {
  allow_methods?: string[];
  allow_contracts?: string[];
  owned_contracts?: string[];
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
}

export interface CreateContractOwnershipInput {
  contract_address: string;
  owner_group_id: string;
  owner_abilities?: string[];
  metadata?: Record<string, unknown>;
}

export interface UpdateContractOwnershipInput {
  owner_group_id?: string;
  owner_abilities?: string[];
  metadata?: Record<string, unknown>;
}

// All available claims for reference
export const ALL_CLAIMS: Claim[] = ['reader', 'writer', 'deployer', 'admin', 'upgrade'];

// Claim labels for display
export const CLAIM_LABELS: Record<Claim, string> = {
  reader: 'Reader',
  writer: 'Writer',
  deployer: 'Deployer',
  admin: 'Admin',
  upgrade: 'Upgrade',
};

// Claim descriptions for tooltips
export const CLAIM_DESCRIPTIONS: Record<Claim, string> = {
  reader: 'Can read data from contracts',
  writer: 'Can write/execute transactions',
  deployer: 'Can deploy new contracts',
  admin: 'Administrative access to group',
  upgrade: 'Can upgrade contracts',
};
