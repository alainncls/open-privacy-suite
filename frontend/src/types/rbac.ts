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
  abi?: string; // Contract ABI JSON for function-level access control
  deployed_by_user_id?: string | null;
  deployed_at?: string | null;
  owner_group_id?: string; // legacy format - deprecated
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}


// ContractGrant - links groups to contracts, enabling access
// Group's claims (from GroupAccess) apply to this contract.
// Functions can optionally restrict which contract functions are accessible.
export interface ContractGrant {
  id: string;
  contract_id: string;
  group_id: string;
  functions?: string[] | null; // null = all functions, or specific selectors
  created_at: string;
  updated_at: string;
}

// GroupAccess - RPC method permissions and rate limits for a group
// Claims define the capabilities group members have (read, write, deploy, admin, upgrade)
export interface GroupAccess {
  id: string;
  group_id: string;
  allowed_methods: string[];
  claims: Claim[]; // Group capabilities - applies to public contracts directly, registered via grants
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
  claims: Claim[]; // User's capabilities from their groups
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
  claims?: Claim[];
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
// Claims are inherited from the group's GroupAccess.claims
export interface CreateContractGrantInput {
  group_id: string;
  functions?: string[] | null;
}

export interface UpdateContractGrantInput {
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
  read: 'Can read contract data (eth_call, eth_estimateGas)',
  write: 'Can send transactions (eth_sendTransaction)',
  admin: 'Full control — implies Read, Write, Deploy, and Upgrade',
  upgrade: 'Can upgrade proxy contract implementations — implies Read and Write',
  deploy: 'Can deploy new contracts to new addresses — implies Read and Write',
};

// Claims hierarchy: which claims each claim implies
export const CLAIM_HIERARCHY: Partial<Record<Claim, Claim[]>> = {
  admin: ['read', 'write', 'deploy', 'upgrade'],
  deploy: ['read', 'write'],
  upgrade: ['read', 'write'],
};

// Get all claims implied by a given claim
export function getImpliedClaims(claim: Claim): Claim[] {
  return CLAIM_HIERARCHY[claim] || [];
}

// Returns which selected claim implies the given claim, or null if none
export function getImplyingClaim(claim: Claim, selectedClaims: Claim[]): Claim | null {
  for (const selected of selectedClaims) {
    const implied = CLAIM_HIERARCHY[selected];
    if (implied && implied.includes(claim)) {
      return selected;
    }
  }
  return null;
}

// RPC methods classified by required claim
// This must match the backend classification in internal/rbac/method_claim.go
export const RPC_METHODS_BY_CLAIM: Record<'read' | 'write', readonly string[]> = {
  read: [
    // Chain/Network info
    'eth_chainId',
    'eth_blockNumber',
    'net_version',
    'net_listening',
    'net_peerCount',
    'web3_clientVersion',
    'web3_sha3',
    'eth_syncing',
    'eth_accounts',
    // Account/Balance queries
    'eth_getBalance',
    'eth_getCode',
    'eth_getStorageAt',
    'eth_getTransactionCount',
    // Block queries
    'eth_getBlockByHash',
    'eth_getBlockByNumber',
    'eth_getBlockTransactionCountByHash',
    'eth_getBlockTransactionCountByNumber',
    // Transaction queries
    'eth_getTransactionByHash',
    'eth_getTransactionReceipt',
    'eth_getTransactionByBlockHashAndIndex',
    'eth_getTransactionByBlockNumberAndIndex',
    // Contract calls (read-only)
    'eth_call',
    'eth_estimateGas',
    // Gas price queries
    'eth_gasPrice',
    'eth_maxPriorityFeePerGas',
    'eth_feeHistory',
    // Logs
    'eth_getLogs',
    // Filter methods
    'eth_newFilter',
    'eth_newBlockFilter',
    'eth_newPendingTransactionFilter',
    'eth_getFilterChanges',
    'eth_getFilterLogs',
    'eth_uninstallFilter',
  ] as const,
  write: [
    'eth_sendTransaction',
    'eth_sendRawTransaction',
    'eth_sign',
    'eth_signTransaction',
    'personal_sign',
    'eth_signTypedData',
    'eth_signTypedData_v4',
  ] as const,
};

// All RPC methods (flattened list)
export const ALL_RPC_METHODS = [
  ...RPC_METHODS_BY_CLAIM.read,
  ...RPC_METHODS_BY_CLAIM.write,
] as const;

// Helper to get required claim for a method
export function getClaimForMethod(method: string): 'read' | 'write' | null {
  if ((RPC_METHODS_BY_CLAIM.read as readonly string[]).includes(method)) {
    return 'read';
  }
  if ((RPC_METHODS_BY_CLAIM.write as readonly string[]).includes(method)) {
    return 'write';
  }
  return null;
}

// Preregistered Address - for CREATE3 address pre-registration
export interface PreregisteredAddress {
  id: string;
  org_id: string;
  address: string;
  factory: string;
  salt: string; // Hex-encoded
  note?: string;
  constructor_abi?: string; // Contract ABI JSON for constructor arg validation
  created_at: string;
  used_at?: string | null;
}

// Input for preregistering addresses
export interface PreregisterInput {
  factory: string;
  salt_prefix: string;
  count: number;
  note?: string;
}

// Response from preregister endpoint
export interface PreregisterResponse {
  addresses: PreregisteredAddress[];
}

// Contract sync status - for checking contracts against chain
export interface ContractSyncStatus {
  id: string;
  address: string;
  name: string;
  status: 'exists' | 'missing' | 'error';
  error?: string;
}

// Response from sync-check endpoint
export interface ContractSyncCheckResponse {
  total: number;
  existing: ContractSyncStatus[];
  missing: ContractSyncStatus[];
  errors: ContractSyncStatus[];
}

// Response from sync-delete endpoint
export interface ContractSyncDeleteResponse {
  deleted_count: number;
  deleted_addresses: string[];
  skipped: Array<{
    id: string;
    reason: string;
  }>;
}
