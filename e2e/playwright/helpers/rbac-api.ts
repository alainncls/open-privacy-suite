import { APIRequestContext } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

// === Types ===

export type Claim = 'reader' | 'writer' | 'deployer' | 'admin' | 'upgrade';

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

export interface GroupPermissions {
  id: string;
  group_id: string;
  allow_methods: string[];
  allow_contracts: string[];
  owned_contracts: string[];
  contract_functions?: Record<string, string[]>; // contract_address -> allowed function selectors
  rate_limit_rps: number | null;
  rate_limit_daily: number | null;
  created_at: string;
  updated_at: string;
}

export interface Role {
  id: string;
  org_id: string;
  name: string;
  description: string;
  claims: Claim[];
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

export interface UserMembership {
  id: string;
  user_id: string;
  group_id: string;
  role_id: string | null;
  source: 'admin' | 'zk_attested';
  zk_credential_ref: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ContractOwnership {
  id: string;
  contract_address: string;
  org_id: string;
  owner_group_id: string;
  owner_abilities: string[];
  deployed_by_user_id: string | null;
  deployed_at: string | null;
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
  contract_functions?: Record<string, string[]>; // contract_address -> allowed function selectors
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
  contract_address?: string;
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

export interface SetGroupPermissionsInput {
  allow_methods?: string[];
  allow_contracts?: string[];
  owned_contracts?: string[];
  contract_functions?: Record<string, string[]>; // contract_address -> allowed function selectors
  rate_limit_rps?: number;
  rate_limit_daily?: number;
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
  role_id?: string;
}

export interface CreateContractInput {
  contract_address: string;
  owner_group_id: string;
  owner_abilities?: string[];
  metadata?: Record<string, unknown>;
}

export interface UpdateContractInput {
  owner_group_id?: string;
  owner_abilities?: string[];
  metadata?: Record<string, unknown>;
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

  async getGroupPermissions(orgId: string, groupId: string): Promise<GroupPermissions | null> {
    const response = await this.request.get(
      `${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}/permissions`
    );
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get group permissions: ${response.status()} - ${body}`);
    }
    return (await response.json()) as GroupPermissions;
  }

  async setGroupPermissions(
    orgId: string,
    groupId: string,
    input: SetGroupPermissionsInput
  ): Promise<GroupPermissions> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/orgs/${orgId}/groups/${groupId}/permissions`,
      {
        headers: { 'Content-Type': 'application/json' },
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to set group permissions: ${response.status()} - ${body}`);
    }
    return (await response.json()) as GroupPermissions;
  }

  // === Roles ===

  async listRoles(orgId: string): Promise<Role[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}/roles`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list roles: ${response.status()} - ${body}`);
    }
    const roles = (await response.json()) as Role[] | null;
    return roles ?? [];
  }

  async createRole(orgId: string, input: CreateRoleInput): Promise<Role> {
    const response = await this.request.post(`${ADMIN_URL}/api/orgs/${orgId}/roles`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create role: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Role;
  }

  async getRole(orgId: string, roleId: string): Promise<Role | null> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}/roles/${roleId}`);
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get role: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Role;
  }

  async updateRole(orgId: string, roleId: string, input: UpdateRoleInput): Promise<Role> {
    const response = await this.request.put(`${ADMIN_URL}/api/orgs/${orgId}/roles/${roleId}`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update role: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Role;
  }

  async deleteRole(orgId: string, roleId: string): Promise<void> {
    const response = await this.request.delete(`${ADMIN_URL}/api/orgs/${orgId}/roles/${roleId}`);
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete role: ${response.status()} - ${body}`);
    }
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

  // === Memberships ===

  async listUserMemberships(userId: string): Promise<UserMembership[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/users/${userId}/memberships`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list user memberships: ${response.status()} - ${body}`);
    }
    const memberships = (await response.json()) as UserMembership[] | null;
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

  async listContracts(orgId: string): Promise<ContractOwnership[]> {
    const response = await this.request.get(`${ADMIN_URL}/api/orgs/${orgId}/contracts`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list contracts: ${response.status()} - ${body}`);
    }
    const contracts = (await response.json()) as ContractOwnership[] | null;
    return contracts ?? [];
  }

  async createContract(orgId: string, input: CreateContractInput): Promise<ContractOwnership> {
    const response = await this.request.post(`${ADMIN_URL}/api/orgs/${orgId}/contracts`, {
      headers: { 'Content-Type': 'application/json' },
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as ContractOwnership;
  }

  async updateContract(
    orgId: string,
    address: string,
    input: UpdateContractInput
  ): Promise<ContractOwnership> {
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
    return (await response.json()) as ContractOwnership;
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
