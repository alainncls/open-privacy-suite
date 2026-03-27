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
  auto_created?: boolean; // True for groups auto-created by deployer auto-grants
  created_at: string;
  updated_at: string;
}

// Batch operation types

export interface BatchMoveRequest {
  contract_ids: string[];
  target_group_id?: string;
  new_group?: { slug: string; name: string };
  delete_empty_auto_groups?: boolean;
}

export interface BatchMoveResponse {
  target_group_id: string;
  moved_count: number;
  deleted_group_ids?: string[];
}

export interface BatchDeleteRequest {
  group_ids: string[];
}

export interface BatchDeleteResponse {
  deleted_count: number;
}

export interface BatchDeletePreviewRequest {
  group_ids: string[];
}

export interface BatchDeletePreviewGroup {
  id: string;
  name: string;
  slug: string;
  auto_created: boolean;
  contract_count: number;
  member_count: number;
  contracts: string[];
}

export interface BatchDeletePreviewResponse {
  groups: BatchDeletePreviewGroup[];
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


// FunctionRule describes access to a single contract function with optional parameter constraints
export interface FunctionRule {
  selector: string;
  param_rules?: ParamRule[] | null;
}

// ParamRule constrains a single ABI parameter of a function call
export interface ParamRule {
  index: number;     // ABI parameter position (0-based)
  must_be: string;   // constraint type: "self" for now
}

// EventRule describes visibility of a single contract event with optional parameter constraints
export interface EventRule {
  topic0: string;    // keccak256(EventName(paramTypes)) — 32-byte hex with 0x prefix
  name: string;      // human-readable event name, from ABI
  param_rules?: ParamRule[] | null;
}

// EventSignature returned by GET /orgs/:org_id/contracts/:address/events
export interface EventSignature {
  name: string;        // e.g. "Transfer"
  signature: string;   // e.g. "Transfer(address,address,uint256)"
  topic0: string;      // keccak256 of signature, hex-encoded with 0x prefix
  inputs: EventInput[];
}

// EventInput describes one parameter of an event
export interface EventInput {
  name: string;
  type: string;    // ABI type string (e.g. "address", "uint256")
  indexed: boolean;
}

// ContractGrant - links groups to contracts, enabling access
// Group's claims (from GroupAccess) apply to this contract.
// Functions can optionally restrict which contract functions are accessible.
export interface ContractGrant {
  id: string;
  contract_id: string;
  group_id: string;
  functions?: FunctionRule[] | null; // null = all functions, or structured rules with optional param constraints
  event_rules?: EventRule[] | null;  // null = all events visible, or allowlist of events with optional param constraints
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
  // Computed fields (populated by backend for child groups)
  effective_claims?: Claim[];
  narrowed_by_parent?: boolean;
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
  functions?: FunctionRule[] | null;    // null = all functions allowed
  event_rules?: EventRule[] | null;     // null = all events visible
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
  functions?: FunctionRule[] | null;
  event_rules?: EventRule[] | null;
}

export interface UpdateContractGrantInput {
  functions?: FunctionRule[] | null;
  event_rules?: EventRule[] | null;
}

// Paginated response envelope from backend list endpoints
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

// Group with inline access settings (returned by paginated groups list)
export interface GroupWithAccess {
  group: Group;
  access: GroupAccess | null;
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

export const METHOD_CATEGORIES = {
  read: {
    'Chain & Network Info': [
      'eth_chainId',
      'eth_blockNumber',
      'net_version',
      'net_listening',
      'net_peerCount',
      'web3_clientVersion',
      'web3_sha3',
      'eth_syncing',
      'eth_accounts',
    ],
    'Accounts & Blocks': [
      'eth_getBalance',
      'eth_getTransactionCount',
      'eth_getBlockByHash',
      'eth_getBlockByNumber',
      'eth_getBlockTransactionCountByHash',
      'eth_getBlockTransactionCountByNumber',
    ],
    'Past Activity (Explorer & Logs)': [
      'eth_getTransactionByHash',
      'eth_getTransactionReceipt',
      'eth_getTransactionByBlockHashAndIndex',
      'eth_getTransactionByBlockNumberAndIndex',
      'eth_getLogs',
    ],
    'Contract Execution': [
      'eth_call',
      'eth_estimateGas',
    ],
    'Deep State Inspection': [
      'eth_getCode',
      'eth_getStorageAt',
    ],
    'Gas & Fee Data': [
      'eth_gasPrice',
      'eth_maxPriorityFeePerGas',
      'eth_feeHistory',
    ],
    'Filters (Deprecated)': [
      'eth_newFilter',
      'eth_newBlockFilter',
      'eth_newPendingTransactionFilter',
      'eth_getFilterChanges',
      'eth_getFilterLogs',
      'eth_uninstallFilter',
    ],
  },
  write: {
    'State Modifying': [
      'eth_sendTransaction',
      'eth_sendRawTransaction',
    ],
    'Signing & Wallets': [
      'eth_sign',
      'eth_signTransaction',
      'personal_sign',
      'eth_signTypedData',
      'eth_signTypedData_v4',
    ],
  },
  deploy: {
    'Advanced Tracing': [
      'debug_traceTransaction',
      'debug_traceCall',
    ],
  },
} as const;

// RPC methods classified by required claim
// This must match the backend classification in internal/rbac/method_claim.go
export const RPC_METHODS_BY_CLAIM: Record<'read' | 'write' | 'deploy', readonly string[]> = {
  read: Object.values(METHOD_CATEGORIES.read).flat() as unknown as readonly string[],
  write: Object.values(METHOD_CATEGORIES.write).flat() as unknown as readonly string[],
  deploy: Object.values(METHOD_CATEGORIES.deploy).flat() as unknown as readonly string[],
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

// Azure AD Tenant Allowlist
export interface AllowedAzureTenant {
  id: string;
  tenant_id: string;
  label: string;
  default_org_id?: string | null;
  default_group_id?: string | null;
  auto_provision: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateAzureTenantInput {
  tenant_id: string;
  label?: string;
  default_org_id?: string | null;
  default_group_id?: string | null;
  auto_provision?: boolean;
}

export interface UpdateAzureTenantInput {
  tenant_id?: string;
  label?: string;
  default_org_id?: string | null;
  default_group_id?: string | null;
  auto_provision?: boolean;
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
