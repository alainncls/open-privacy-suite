import axios from 'axios';
import type {
  Organization,
  Group,
  User,
  UserMembership,
  GroupAccess,
  Contract,
  ContractGrant,
  EffectivePermissions,
  AccessCheckRequest,
  AccessCheckResult,
  CacheStats,
  CreateOrganizationInput,
  UpdateOrganizationInput,
  CreateGroupInput,
  UpdateGroupInput,
  UpdateUserInput,
  CreateMembershipInput,
  SetGroupAccessInput,
  CreateContractInput,
  UpdateContractInput,
  CreateContractGrantInput,
  UpdateContractGrantInput,
  MembershipWithDetails,
  PreregisteredAddress,
  PreregisterInput,
  PreregisterResponse,
  ContractSyncCheckResponse,
  ContractSyncDeleteResponse,
  PaginatedResponse,
  GroupWithAccess,
} from '../types/rbac';

const api = axios.create({
  baseURL: '/api/v1/admin',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const rbacApi = {
  // Organizations
  orgs: {
    list: (params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<Organization>>('/orgs', { params }),
    get: (orgId: string) => api.get<Organization>(`/orgs/${orgId}`),
    create: (input: CreateOrganizationInput) => api.post<Organization>('/orgs', input),
    update: (orgId: string, input: UpdateOrganizationInput) =>
      api.put<Organization>(`/orgs/${orgId}`, input),
    delete: (orgId: string) => api.delete(`/orgs/${orgId}`),
  },

  // Groups
  groups: {
    list: (orgId: string, params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<GroupWithAccess>>(`/orgs/${orgId}/groups`, { params }),
    get: (orgId: string, groupId: string) =>
      api.get<Group>(`/orgs/${orgId}/groups/${groupId}`),
    create: (orgId: string, input: CreateGroupInput) =>
      api.post<Group>(`/orgs/${orgId}/groups`, input),
    update: (orgId: string, groupId: string, input: UpdateGroupInput) =>
      api.put<Group>(`/orgs/${orgId}/groups/${groupId}`, input),
    delete: (orgId: string, groupId: string) =>
      api.delete(`/orgs/${orgId}/groups/${groupId}`),
    // Group access (replaces old permissions and roles)
    getAccess: (orgId: string, groupId: string) =>
      api.get<GroupAccess>(`/orgs/${orgId}/groups/${groupId}/access`),
    setAccess: (orgId: string, groupId: string, input: SetGroupAccessInput) =>
      api.put<GroupAccess>(`/orgs/${orgId}/groups/${groupId}/access`, input),
  },

  // Users
  users: {
    list: (params?: { limit?: number; offset?: number; org_id?: string; search?: string }) =>
      api.get<PaginatedResponse<User>>('/users', { params }),
    get: (userId: string) => api.get<User>(`/users/${userId}`),
    update: (userId: string, input: UpdateUserInput) =>
      api.put<User>(`/users/${userId}`, input),
    getMemberships: (userId: string) =>
      api.get<MembershipWithDetails[]>(`/users/${userId}/memberships`),
    createMembership: (userId: string, input: CreateMembershipInput) =>
      api.post<UserMembership>(`/users/${userId}/memberships`, input),
    deleteMembership: (userId: string, membershipId: string) =>
      api.delete(`/users/${userId}/memberships/${membershipId}`),
    getEffectivePermissions: (userId: string, orgSlug?: string) =>
      api.get<EffectivePermissions>(`/users/${userId}/effective-permissions`, {
        params: { org: orgSlug },
      }),
    getLinkedAddresses: (userId: string) =>
      api.get<{ addresses: Array<{ address: string; verified_at: string }> }>(
        `/users/${userId}/linked-addresses`
      ),
  },

  // Contracts (first-class resources)
  contracts: {
    list: (orgId: string, params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<Contract>>(`/orgs/${orgId}/contracts`, { params }),
    get: (orgId: string, address: string) =>
      api.get<Contract>(`/orgs/${orgId}/contracts/${address}`),
    create: (orgId: string, input: CreateContractInput) =>
      api.post<Contract>(`/orgs/${orgId}/contracts`, input),
    update: (orgId: string, address: string, input: UpdateContractInput) =>
      api.put<Contract>(`/orgs/${orgId}/contracts/${address}`, input),
    delete: (orgId: string, address: string) =>
      api.delete(`/orgs/${orgId}/contracts/${address}`),
    // Contract grants
    listGrants: (orgId: string, address: string) =>
      api.get<ContractGrant[]>(`/orgs/${orgId}/contracts/${address}/grants`),
    createGrant: (orgId: string, address: string, input: CreateContractGrantInput) =>
      api.post<ContractGrant>(`/orgs/${orgId}/contracts/${address}/grants`, input),
    updateGrant: (orgId: string, address: string, groupId: string, input: UpdateContractGrantInput) =>
      api.put<ContractGrant>(`/orgs/${orgId}/contracts/${address}/grants/${groupId}`, input),
    deleteGrant: (orgId: string, address: string, groupId: string) =>
      api.delete(`/orgs/${orgId}/contracts/${address}/grants/${groupId}`),
    // ABI management
    updateABI: (orgId: string, address: string, abi: string) =>
      api.put<Contract>(`/orgs/${orgId}/contracts/${address}/abi`, { abi }),
    // Sync with chain
    syncCheck: (orgId: string) =>
      api.post<ContractSyncCheckResponse>(`/orgs/${orgId}/contracts/sync-check`),
    syncDelete: (orgId: string, contractIds: string[]) =>
      api.post<ContractSyncDeleteResponse>(`/orgs/${orgId}/contracts/sync-delete`, { contract_ids: contractIds }),
    // Lookup by address (cross-org, for test request panel)
    lookupByAddress: (address: string) =>
      api.get<{
        contract: Contract;
        organization: Organization;
        grants: Array<{
          grant: ContractGrant;
          group: Group;
          access: GroupAccess | null;
        }>;
      }>(`/contracts/by-address/${address}`),
  },

  // Preregistered Addresses (CREATE3)
  preregisteredAddresses: {
    list: (orgId: string) =>
      api.get<PreregisteredAddress[]>(`/orgs/${orgId}/addresses/preregistered`),
    create: (orgId: string, input: PreregisterInput) =>
      api.post<PreregisterResponse>(`/orgs/${orgId}/addresses/preregister`, input),
    delete: (orgId: string, address: string) =>
      api.delete(`/orgs/${orgId}/addresses/preregistered/${encodeURIComponent(address)}`),
    updateABI: (orgId: string, address: string, constructorABI: string) =>
      api.put(`/orgs/${orgId}/addresses/preregistered/${encodeURIComponent(address)}/abi`, {
        constructor_abi: constructorABI,
      }),
  },

  // Utilities
  utils: {
    checkAccess: (request: AccessCheckRequest) =>
      api.post<AccessCheckResult>('/access/check', request),
    getCacheStats: () => api.get<CacheStats>('/cache/stats'),
  },

  // System status
  status: {
    get: () =>
      api.get<{
        proxy: { status: string; port: string };
        node: { status: string; url: string; latency_ms: number; error?: string };
        security: { runtime_tracing_enabled: boolean };
      }>('/status'),
  },

  // Org config endpoints
  orgConfig: {
    getCreate3Factory: (orgId: string) =>
      api.get<{ factory: string; configured: boolean; message?: string }>(`/orgs/${orgId}/config/create3`),
    setCreate3Factory: (orgId: string, factory: string) =>
      api.put<{ factory: string; configured: boolean }>(`/orgs/${orgId}/config/create3`, { factory }),
  },

  // Dev endpoints (only available in development mode)
  dev: {
    getCreate3Factory: () =>
      api.get<{ address: string; deployed: boolean; message?: string }>('/dev/create3-factory'),
    deployCreate3Factory: () =>
      api.post<{ address: string; deployed: boolean }>('/dev/create3-factory'),
    autoRegisterCreate3: (orgId: string, input: { factory: string; salt: string; name?: string }) =>
      api.post<{ address: string; registered: boolean; message?: string }>(
        `/dev/orgs/${orgId}/create3/auto-register`,
        input
      ),
  },
};

export default rbacApi;
