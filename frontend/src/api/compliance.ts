import api from './client';
import type {
  ComplianceConfig,
  UpdateComplianceConfigInput,
  TokenPrice,
  UpsertTokenPriceInput,
  TravelRuleRecord,
  CreateTravelRuleRecordInput,
  SanctionedAddress,
  AddSanctionedAddressInput,
  ComplianceLog,
  ComplianceLogFilters,
  PaginatedResponse,
} from '../types/compliance';

export const complianceApi = {
  config: {
    get: (orgId: string) =>
      api.get<ComplianceConfig>(`/admin/orgs/${orgId}/compliance/config`),
    update: (orgId: string, input: UpdateComplianceConfigInput) =>
      api.put<ComplianceConfig>(`/admin/orgs/${orgId}/compliance/config`, input),
  },

  tokens: {
    list: (orgId: string) =>
      api.get<TokenPrice[]>(`/admin/orgs/${orgId}/compliance/tokens`),
    upsert: (orgId: string, tokenAddress: string, input: UpsertTokenPriceInput) =>
      api.put<TokenPrice>(`/admin/orgs/${orgId}/compliance/tokens/${encodeURIComponent(tokenAddress)}`, input),
    delete: (orgId: string, tokenAddress: string) =>
      api.delete(`/admin/orgs/${orgId}/compliance/tokens/${encodeURIComponent(tokenAddress)}`),
  },

  travelRules: {
    list: (orgId: string, params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<TravelRuleRecord>>(`/admin/orgs/${orgId}/compliance/travel-rule-records`, { params }),
    create: (orgId: string, input: CreateTravelRuleRecordInput) =>
      api.post<TravelRuleRecord>(`/admin/orgs/${orgId}/compliance/travel-rule-records`, input),
  },

  sanctions: {
    list: (params?: { org_id?: string; limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<SanctionedAddress>>('/admin/compliance/sanctions', { params }),
    add: (input: AddSanctionedAddressInput) =>
      api.post<SanctionedAddress>('/admin/compliance/sanctions', input),
    remove: (id: string) =>
      api.delete(`/admin/compliance/sanctions/${id}`),
  },

  logs: {
    list: (orgId: string, params?: ComplianceLogFilters) =>
      api.get<PaginatedResponse<ComplianceLog>>(`/admin/orgs/${orgId}/compliance/logs`, { params }),
  },
};
