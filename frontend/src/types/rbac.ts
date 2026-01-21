// RBAC TypeScript types mirroring backend models

// Claims: read, write, admin, upgrade, deploy
export type Claim = 'read' | 'write' | 'admin' | 'upgrade' | 'deploy';

export type MembershipSource = 'admin' | 'zk_attested';

export interface Organization {
  id: string;
  slug: string;
  name: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// Group - no more role_id (permissions come from GroupAccess and ContractGrants)
export interface Group {
  id: string;
  org_id: string;
  parent_id?: string | null;
  slug: string;
  name: string;
  description?: string;
  depth: number;
  path: string; // Materialized path (e.g., "root.engineering.devops")
  is_org_admin?: boolean; // If true, members get all claims on all contracts in the org
  created_at: string;
  updated_at: string;
}

// Contract - first-class resource
export interface Contract {
  id: string;
  org_id: string;
  address?: string; // lowercase 0x-prefixed (new format)
  contract_address?: string; // legacy format - deprecated
  name?: string;
  deployed_by_user_id?: string | null;
  deployed_at?: string | null;
  owner_group_id?: string; // legacy format - deprecated
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}


// ContractGrant - links groups to contracts with claims
export interface ContractGrant {
  id: string;
  contract_id: string;
  group_id: string;
  claims: Claim[];
  functions?: string[] | null; // null = all functions, or specific selectors
  created_at: string;
  updated_at: string;
}

// GroupAccess - RPC method permissions and rate limits for a group
export interface GroupAccess {
  id: string;
  group_id: string;
  allowed_methods: string[];
  default_claims: Claim[]; // Claims for unregistered contracts
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

// UserMembership - no more role_id (permissions come from group)
export interface UserMembership {
  id: string;
  user_id: string;
  group_id: string;
  source: MembershipSource;
  zk_credential_ref?: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ContractAccess - access permissions for a specific contract
export interface ContractAccess {
  claims: Claim[];
  functions?: string[] | null; // null = all functions allowed
}

// EffectivePermissions - computed permissions for a user
export interface EffectivePermissions {
  id: string;
  user_id: string;
  org_id: string;
  allowed_methods: string[];
  contract_access: Record<string, ContractAccess>; // address -> access
  default_claims: Claim[]; // Claims for unregistered contracts
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
  computed_at: string;
  expires_at: string;
}

// MembershipWithDetails - no more role field
export interface MembershipWithDetails {
  membership: UserMembership;
  group: Group;
}

export interface AccessCheckRequest {
  user_external_id: string;
  org_slug?: string;
  method: string;
  target_address?: string;
  function_selector?: string;
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

// No more role_id in group creation
export interface CreateGroupInput {
  slug: string;
  name: string;
  description?: string;
  parent_id?: string | null;
  is_org_admin?: boolean;
}

export interface UpdateGroupInput {
  name?: string;
  description?: string;
  is_org_admin?: boolean;
}

// Input for setting group access
export interface SetGroupAccessInput {
  allowed_methods?: string[];
  default_claims?: Claim[];
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
}

export interface UpdateUserInput {
  kyc?: boolean;
  banned?: boolean;
  note?: string;
  metadata?: Record<string, unknown>;
}

// No more role_id in membership creation
export interface CreateMembershipInput {
  group_id: string;
}

// Input for creating a contract
export interface CreateContractInput {
  address: string;
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateContractInput {
  name?: string;
  metadata?: Record<string, unknown>;
}

// Input for creating a contract grant
export interface CreateContractGrantInput {
  group_id: string;
  claims: Claim[];
  functions?: string[] | null;
}

export interface UpdateContractGrantInput {
  claims?: Claim[];
  functions?: string[] | null;
}

// All available claims for reference
export const ALL_CLAIMS: Claim[] = ['read', 'write', 'admin', 'upgrade', 'deploy'];

// Claim labels for display
export const CLAIM_LABELS: Record<Claim, string> = {
  read: 'Read',
  write: 'Write',
  admin: 'Admin',
  upgrade: 'Upgrade',
  deploy: 'Deploy',
};

// Claim descriptions for tooltips
export const CLAIM_DESCRIPTIONS: Record<Claim, string> = {
  read: 'Can read data from contracts (eth_call, eth_estimateGas)',
  write: 'Can write/execute transactions (eth_sendTransaction)',
  admin: 'Full control - considered owner of the contract',
  upgrade: 'Can upgrade proxy contracts',
  deploy: 'Can deploy new contracts (contract creation transactions)',
};
