import { APIRequestContext } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

// === Types ===

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

export interface Group {
  id: string;
  org_id: string;
  parent_id: string | null;
  slug: string;
  name: string;
  description: string;
  depth: number;
  path: string;
  created_at: string;
  updated_at: string;
}

// GroupAccess - RPC method permissions and rate limits for a group (replaces old GroupPermissions)
export interface GroupAccess {
  id: string;
  group_id: string;
  allowed_methods: string[];
  claims: Claim[];
  rate_limit_rps: number | null;
  rate_limit_daily: number | null;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  external_id: string;
  kyc: boolean;
  banned: boolean;
  note: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface LinkedAddress {
  address: string;
  verified_at: string;
  ens_name?: string;
  ens_resolved_at?: string;
}

export interface UserMembership {
  id: string;
  user_id: string;
  group_id: string;
  source: MembershipSource;
  zk_credential_ref: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface MembershipWithDetails {
  membership: UserMembership;
  group: Group;
}

// Contract - first-class resource (replaces old ContractOwnership)
export interface Contract {
  id: string;
  org_id: string;
  address?: string; // new format
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

// Helper to get contract address from either format
export function getContractAddress(contract: Contract): string {
  return contract.address || contract.contract_address || '';
}

// FunctionRule - structured function selector with optional parameter constraints
export interface FunctionRule {
  selector: string;
  param_rules?: ParamRule[];
}

// ParamRule - constrains a single ABI parameter of a function call
export interface ParamRule {
  index: number;
  must_be: string; // "self" for now
}

// ContractGrant - links groups to contracts (claims are inherited from GroupAccess)
export interface ContractGrant {
  id: string;
  contract_id: string;
  group_id: string;
  functions?: FunctionRule[] | null; // null = all functions, or structured rules
  created_at: string;
  updated_at: string;
}

// ContractAccess - per-contract permissions in EffectivePermissions
export interface ContractAccess {
  claims: Claim[];
  functions?: FunctionRule[] | null;
}

// Helper to extract selector strings from FunctionRule arrays (for assertions)
export function selectorsOf(functions: FunctionRule[] | null | undefined): string[] | null {
  if (functions == null) return null;
  return functions.map((f) => f.selector);
}

export interface EffectivePermissions {
  id: string;
  user_id: string;
  org_id: string;
  allowed_methods: string[];
  contract_access: Record<string, ContractAccess>; // address -> access
  claims: Claim[];
  rate_limit_rps: number | null;
  rate_limit_daily: number | null;
  computed_at: string;
  expires_at: string;
}

export interface AccessCheckRequest {
  user_external_id: string;
  org_slug?: string;
  method: string;
  target_address?: string;
  function_selector?: string; // First 4 bytes of calldata (e.g., "0xa9059cbb")
  required_claims?: Claim[];
}

export interface AccessCheckResult {
  allowed: boolean;
  reason?: string;
  rate_limit_rps?: number;
  rate_limit_daily?: number;
  claims?: Claim[];
}

export interface CacheStats {
  entries: number;
  expired_pending: number;
  max_entries: number;
}

// === Input Types ===

export interface CreateOrgInput {
  slug: string;
  name: string;
  settings?: Record<string, unknown>;
}

export interface UpdateOrgInput {
  slug?: string;
  name?: string;
  settings?: Record<string, unknown>;
}

export interface CreateGroupInput {
  slug: string;
  name: string;
  description?: string;
  parent_id?: string;
}

export interface UpdateGroupInput {
  name?: string;
  description?: string;
}

export interface SetGroupAccessInput {
  allowed_methods?: string[];
  claims?: Claim[];
  rate_limit_rps?: number;
  rate_limit_daily?: number;
}

export interface UpdateUserInput {
  kyc?: boolean;
  banned?: boolean;
  note?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateMembershipInput {
  group_id: string;
}

export interface CreateContractInput {
  address: string;
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateContractInput {
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateContractGrantInput {
  group_id: string;
  functions?: FunctionRule[] | null;
}

export interface UpdateContractGrantInput {
  functions?: FunctionRule[] | null;
}

// Shorthand: convert a selector string to a FunctionRule with no param constraints.
export function fn(selector: string): FunctionRule {
  return { selector };
}

// Shorthand: convert an array of selector strings to FunctionRule[].
export function fns(...selectors: string[]): FunctionRule[] {
  return selectors.map((s) => ({ selector: s }));
}

// === API Client ===

export class RBACApiClient {
  constructor(private request: APIRequestContext) {}

  // === Organizations ===

  async listOrganizations(): Promise<Organization[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list organizations: ${response.status()} - ${body}`);
    }
    const orgs = (await response.json()) as Organization[] | null;
    return orgs ?? [];
  }

  async createOrganization(input: CreateOrgInput): Promise<Organization> {
    const response = await this.request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create organization: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Organization;
  }

  async getOrganization(orgId: string): Promise<Organization | null> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}`);
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get organization: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Organization;
  }

  async updateOrganization(orgId: string, input: UpdateOrgInput): Promise<Organization> {
    const response = await this.request.put(`${ADMIN_URL}/api/orgs/${orgId}`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update organization: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Organization;
  }

  // === Groups ===

  async listGroups(orgId: string): Promise<Group[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}/groups`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list groups: ${response.status()} - ${body}`);
    }
    const groups = (await response.json()) as Group[] | null;
    return groups ?? [];
  }

  async createGroup(orgId: string, input: CreateGroupInput): Promise<Group> {
    const response = await this.request.post(`${ADMIN_URL}/api/orgs/${orgId}/groups`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create group: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Group;
  }

  async getGroup(orgId: string, groupId: string): Promise<Group | null> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}`);
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get group: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Group;
  }

  async updateGroup(orgId: string, groupId: string, input: UpdateGroupInput): Promise<Group> {
    const response = await this.request.put(`${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update group: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Group;
  }

  async deleteGroup(orgId: string, groupId: string): Promise<void> {
    const response = await this.request.delete(`${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}`);
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete group: ${response.status()} - ${body}`);
    }
  }

  async getGroupAccess(orgId: string, groupId: string): Promise<GroupAccess | null> {
    const response = await this.request.get(
      `${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}/access`
    );
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get group access: ${response.status()} - ${body}`);
    }
    return (await response.json()) as GroupAccess;
  }

  async setGroupAccess(
    orgId: string,
    groupId: string,
    input: SetGroupAccessInput
  ): Promise<GroupAccess> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}/access`,
      {
        headers: { 'Content-Type': 'application/json' },
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to set group access: ${response.status()} - ${body}`);
    }
    return (await response.json()) as GroupAccess;
  }

  // === Users ===

  async listUsers(limit = 100, offset = 0): Promise<User[]> {
    const response = await this.request.get(
      `${ADMIN_URL}/api/users?limit=${limit}&offset=${offset}`
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list users: ${response.status()} - ${body}`);
    }
    const users = (await response.json()) as User[] | null;
    return users ?? [];
  }

  async getUser(userId: string): Promise<User | null> {
    const response = await this.request.get(`${ADMIN_URL}/api/users/${userId}`);
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get user: ${response.status()} - ${body}`);
    }
    return (await response.json()) as User;
  }

  async updateUser(userId: string, input: UpdateUserInput): Promise<User> {
    const response = await this.request.put(`${ADMIN_URL}/api/users/${userId}`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update user: ${response.status()} - ${body}`);
    }
    return (await response.json()) as User;
  }

  async findUserByExternalId(externalId: string): Promise<User | null> {
    const users = await this.listUsers(1000);
    return users.find((u) => u.external_id === externalId) ?? null;
  }

  // === Linked Addresses ===

  async getUserLinkedAddresses(userId: string): Promise<LinkedAddress[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/users/${userId}/linked-addresses`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get user linked addresses: ${response.status()} - ${body}`);
    }
    const data = (await response.json()) as { addresses: LinkedAddress[] };
    // Verify the response has the expected structure
    if (!data.addresses || !Array.isArray(data.addresses)) {
      throw new Error(`Invalid linked addresses response format: expected {addresses: [...]}, got ${JSON.stringify(data)}`);
    }
    return data.addresses;
  }

  // === Memberships ===

  async listUserMemberships(userId: string): Promise<MembershipWithDetails[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/users/${userId}/memberships`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list user memberships: ${response.status()} - ${body}`);
    }
    const memberships = (await response.json()) as MembershipWithDetails[] | null;
    return memberships ?? [];
  }

  async createMembership(userId: string, input: CreateMembershipInput): Promise<UserMembership> {
    const response = await this.request.post(`${ADMIN_URL}/api/users/${userId}/memberships`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create membership: ${response.status()} - ${body}`);
    }
    return (await response.json()) as UserMembership;
  }

  async deleteMembership(userId: string, membershipId: string): Promise<void> {
    const response = await this.request.delete(
      `${ADMIN_URL}/api/users/${userId}/memberships/${membershipId}`
    );
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete membership: ${response.status()} - ${body}`);
    }
  }

  // === Contracts ===

  async listContracts(orgId: string): Promise<Contract[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}/contracts`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list contracts: ${response.status()} - ${body}`);
    }
    const contracts = (await response.json()) as Contract[] | null;
    return contracts ?? [];
  }

  async createContract(orgId: string, input: CreateContractInput): Promise<Contract> {
    const response = await this.request.post(`${ADMIN_URL}/api/orgs/${orgId}/contracts`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async updateContract(
    orgId: string,
    address: string,
    input: UpdateContractInput
  ): Promise<Contract> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}`,
      {
        headers: { 'Content-Type': 'application/json' },
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async deleteContract(orgId: string, address: string): Promise<void> {
    const response = await this.request.delete(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}`
    );
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete contract: ${response.status()} - ${body}`);
    }
  }

  async getContract(orgId: string, address: string): Promise<Contract | null> {
    const response = await this.request.get(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}`
    );
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async updateContractABI(orgId: string, address: string, abi: string): Promise<Contract> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}/abi`,
      {
        headers: { 'Content-Type': 'application/json' },
        data: { abi },
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update contract ABI: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  // === Contract Grants ===

  async listContractGrants(orgId: string, address: string): Promise<ContractGrant[]> {
    const response = await this.request.get(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}/grants`
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list contract grants: ${response.status()} - ${body}`);
    }
    const grants = (await response.json()) as ContractGrant[] | null;
    return grants ?? [];
  }

  async createContractGrant(
    orgId: string,
    address: string,
    input: CreateContractGrantInput
  ): Promise<ContractGrant> {
    const response = await this.request.post(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}/grants`,
      {
        headers: { 'Content-Type': 'application/json' },
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create contract grant: ${response.status()} - ${body}`);
    }
    return (await response.json()) as ContractGrant;
  }

  async updateContractGrant(
    orgId: string,
    address: string,
    groupId: string,
    input: UpdateContractGrantInput
  ): Promise<ContractGrant> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}/grants/${groupId}`,
      {
        headers: { 'Content-Type': 'application/json' },
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update contract grant: ${response.status()} - ${body}`);
    }
    return (await response.json()) as ContractGrant;
  }

  async deleteContractGrant(orgId: string, address: string, groupId: string): Promise<void> {
    const response = await this.request.delete(
      `${ADMIN_URL}/api/orgs/${orgId}/contracts/${address}/grants/${groupId}`
    );
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete contract grant: ${response.status()} - ${body}`);
    }
  }

  // === Access Control ===

  async checkAccess(req: AccessCheckRequest): Promise<AccessCheckResult> {
    const response = await this.request.post(`${ADMIN_URL}/api/access/check`, {
      headers: { 'Content-Type': 'application/json' },
      data: req,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to check access: ${response.status()} - ${body}`);
    }
    return (await response.json()) as AccessCheckResult;
  }

  async getEffectivePermissions(userId: string, orgSlug?: string): Promise<EffectivePermissions> {
    const url = orgSlug
      ? `${ADMIN_URL}/api/users/${userId}/effective-permissions?org=${orgSlug}`
      : `${ADMIN_URL}/api/users/${userId}/effective-permissions`;
    const response = await this.request.get(url);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get effective permissions: ${response.status()} - ${body}`);
    }
    return (await response.json()) as EffectivePermissions;
  }

  async getCacheStats(): Promise<CacheStats> {
    const response = await this.request.get(`${ADMIN_URL}/api/cache/stats`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get cache stats: ${response.status()} - ${body}`);
    }
    return (await response.json()) as CacheStats;
  }
}
