import axios from 'axios';
import type {
  Organization,
  Group,
  Role,
  User,
  UserMembership,
  GroupPermissions,
  ContractOwnership,
  EffectivePermissions,
  AccessCheckRequest,
  AccessCheckResult,
  CacheStats,
  CreateOrganizationInput,
  UpdateOrganizationInput,
  CreateGroupInput,
  UpdateGroupInput,
  CreateRoleInput,
  UpdateRoleInput,
  UpdateUserInput,
  CreateMembershipInput,
  SetGroupPermissionsInput,
  CreateContractOwnershipInput,
  UpdateContractOwnershipInput,
  MembershipWithDetails,
} from '../types/rbac';

const api = axios.create({
  baseURL: '/api',
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
    getPermissions: (orgId: string, groupId: string) =>
      api.get<GroupPermissions>(`/orgs/${orgId}/groups/${groupId}/permissions`),
    setPermissions: (orgId: string, groupId: string, input: SetGroupPermissionsInput) =>
      api.put<GroupPermissions>(`/orgs/${orgId}/groups/${groupId}/permissions`, input),
  },

  // Roles
  roles: {
    list: (orgId: string) => api.get<Role[]>(`/orgs/${orgId}/roles`),
    get: (orgId: string, roleId: string) =>
      api.get<Role>(`/orgs/${orgId}/roles/${roleId}`),
    create: (orgId: string, input: CreateRoleInput) =>
      api.post<Role>(`/orgs/${orgId}/roles`, input),
    update: (orgId: string, roleId: string, input: UpdateRoleInput) =>
      api.put<Role>(`/orgs/${orgId}/roles/${roleId}`, input),
    delete: (orgId: string, roleId: string) =>
      api.delete(`/orgs/${orgId}/roles/${roleId}`),
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

  // Contracts
  contracts: {
    list: (orgId: string) => api.get<ContractOwnership[]>(`/orgs/${orgId}/contracts`),
    create: (orgId: string, input: CreateContractOwnershipInput) =>
      api.post<ContractOwnership>(`/orgs/${orgId}/contracts`, input),
    update: (orgId: string, address: string, input: UpdateContractOwnershipInput) =>
      api.put<ContractOwnership>(`/orgs/${orgId}/contracts/${address}`, input),
    delete: (orgId: string, address: string) =>
      api.delete(`/orgs/${orgId}/contracts/${address}`),
  },

  // Utilities
  utils: {
    checkAccess: (request: AccessCheckRequest) =>
      api.post<AccessCheckResult>('/access/check', request),
    getCacheStats: () => api.get<CacheStats>('/cache/stats'),
  },
};

export default rbacApi;
