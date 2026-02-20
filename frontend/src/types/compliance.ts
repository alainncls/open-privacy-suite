export type TransferType = 'eth' | 'erc20';
export type Decision = 'allowed' | 'denied';

export interface ComplianceConfig {
  id: string;
  org_id: string;
  enabled: boolean;
  threshold_fiat: number;
  created_at: string;
  updated_at: string;
}

export interface UpdateComplianceConfigInput {
  enabled?: boolean;
  threshold_fiat?: number;
}

export interface TokenPrice {
  id: string;
  org_id: string;
  token_address: string;
  symbol: string;
  decimals: number;
  price_fiat: number;
  coingecko_id?: string;
  updated_by_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface UpsertTokenPriceInput {
  symbol: string;
  decimals: number;
  price_fiat: number;
  coingecko_id?: string | null;
}

export interface SystemTokenPrice {
  id: number;
  coingecko_id?: string;
  source: string;
  token_address?: string;
  symbol: string;
  decimals: number;
  price_fiat: number;
  updated_at: string;
  is_stale: boolean;
}

export interface TravelRuleRecord {
  id: string;
  org_id: string;
  originator_user_id: string;
  originator_external_id?: string;
  originator_data: Record<string, unknown>;
  beneficiary_data: Record<string, unknown>;
  transfer_type: TransferType;
  token_address?: string;
  beneficiary_address: string;
  amount_wei: string;
  amount_fiat: number;
  currency: string;
  expires_at: string;
  used_at?: string;
  used_tx_hash?: string;
  created_at: string;
}

export interface CreateTravelRuleRecordInput {
  originator_user_id: string;
  originator_data: Record<string, unknown>;
  beneficiary_data: Record<string, unknown>;
  transfer_type: TransferType;
  token_address?: string;
  beneficiary_address: string;
  amount_wei: string;
}

export interface SanctionedAddress {
  id: string;
  org_id?: string;
  address: string;
  reason: string;
  source?: string;
  added_by_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface AddSanctionedAddressInput {
  org_id?: string;
  address: string;
  reason: string;
  source?: string;
}

export interface ComplianceLog {
  id: number;
  org_id: string;
  user_id: string;
  user_external_id?: string;
  transfer_type: TransferType;
  token_address?: string;
  from_address: string;
  to_address: string;
  amount_wei: string;
  amount_fiat?: number;
  threshold_fiat?: number;
  currency?: string;
  decision: Decision;
  denial_reason?: string;
  travel_rule_record_id?: string;
  created_at: string;
}

export interface AddressThresholdOverride {
  id: string;
  org_id: string;
  address: string;
  threshold_fiat: number;
  note?: string;
  created_at: string;
  updated_at: string;
}

export interface UpsertAddressThresholdInput {
  threshold_fiat: number;
  note?: string;
}

export interface ComplianceLogFilters {
  user_search?: string;
  decision?: Decision;
  transfer_type?: TransferType;
  limit?: number;
  offset?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export type SupportedCurrency = 'usd' | 'eur' | 'chf' | 'gbp' | 'aed';

export interface CurrencyInfo {
  code: string;
  name: string;
  symbol: string;
}

export interface CurrencyConfig {
  currency: string;
  all_currencies: CurrencyInfo[];
}

export interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  permissions: string[];
  expires_at?: string;
  revoked_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface CreateAPIKeyResponse {
  key: string;
  id: string;
  name: string;
  key_prefix: string;
  permissions: string[];
  expires_at?: string;
  created_at: string;
}
