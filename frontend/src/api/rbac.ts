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
} from '../types/rbac';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const rbacApi = {
  // Organizations
  orgs: {
    list: () => api.get<Organization[]>('/orgs'),
    get: (orgId: string) => api.get<Organization>(`/orgs/${orgId}`),
    create: (input: CreateOrganizationInput) => api.post<Organization>('/orgs', input),
    update: (orgId: string, input: UpdateOrganizationInput) =>
      api.put<Organization>(`/orgs/${orgId}`, input),
    delete: (orgId: string) => api.delete(`/orgs/${orgId}`),
  },

  // Groups
  groups: {
    list: (orgId: string) => api.get<Group[]>(`/orgs/${orgId}/groups`),
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
    list: (limit?: number, offset?: number) =>
      api.get<User[]>('/users', { params: { limit, offset } }),
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
    list: (orgId: string) => api.get<Contract[]>(`/orgs/${orgId}/contracts`),
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
  },

  // Utilities
  utils: {
    checkAccess: (request: AccessCheckRequest) =>
      api.post<AccessCheckResult>('/access/check', request),
    getCacheStats: () => api.get<CacheStats>('/cache/stats'),
  },
};

export default rbacApi;
