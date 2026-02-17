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
      api.get<ComplianceConfig>(`/orgs/${orgId}/compliance/config`),
    update: (orgId: string, input: UpdateComplianceConfigInput) =>
      api.put<ComplianceConfig>(`/orgs/${orgId}/compliance/config`, input),
  },

  tokens: {
    list: (orgId: string) =>
      api.get<{ data: TokenPrice[] }>(`/orgs/${orgId}/compliance/tokens`),
    upsert: (orgId: string, tokenAddress: string, input: UpsertTokenPriceInput) =>
      api.put<TokenPrice>(`/orgs/${orgId}/compliance/tokens/${encodeURIComponent(tokenAddress)}`, input),
    delete: (orgId: string, tokenAddress: string) =>
      api.delete(`/orgs/${orgId}/compliance/tokens/${encodeURIComponent(tokenAddress)}`),
  },

  travelRules: {
    list: (orgId: string, params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<TravelRuleRecord>>(`/orgs/${orgId}/compliance/travel-rule-records`, { params }),
    create: (orgId: string, input: CreateTravelRuleRecordInput) =>
      api.post<TravelRuleRecord>(`/orgs/${orgId}/compliance/travel-rule-records`, input),
  },

  sanctions: {
    list: (params?: { org_id?: string; limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<SanctionedAddress>>('/compliance/sanctions', { params }),
    add: (input: AddSanctionedAddressInput) =>
      api.post<SanctionedAddress>('/compliance/sanctions', input),
    remove: (id: string) =>
      api.delete(`/compliance/sanctions/${id}`),
  },

  logs: {
    list: (orgId: string, params?: ComplianceLogFilters) =>
      api.get<PaginatedResponse<ComplianceLog>>(`/orgs/${orgId}/compliance/logs`, { params }),
  },
};
