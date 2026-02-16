export type TransferType = 'eth' | 'erc20';
export type Decision = 'allowed' | 'denied';

export interface ComplianceConfig {
  id: string;
  org_id: string;
  enabled: boolean;
  threshold_usd: number;
  created_at: string;
  updated_at: string;
}

export interface UpdateComplianceConfigInput {
  enabled?: boolean;
  threshold_usd?: number;
}

export interface TokenPrice {
  id: string;
  org_id: string;
  token_address: string;
  symbol: string;
  decimals: number;
  price_usd: number;
  updated_by_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface UpsertTokenPriceInput {
  symbol: string;
  decimals: number;
  price_usd: number;
}

export interface TravelRuleRecord {
  id: string;
  org_id: string;
  originator_user_id: string;
  originator_data: Record<string, unknown>;
  beneficiary_data: Record<string, unknown>;
  transfer_type: TransferType;
  token_address?: string;
  beneficiary_address: string;
  amount_wei: string;
  amount_usd: number;
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
  amount_usd: number;
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
  transfer_type: TransferType;
  token_address?: string;
  from_address: string;
  to_address: string;
  amount_wei: string;
  amount_usd?: number;
  threshold_usd?: number;
  decision: Decision;
  denial_reason?: string;
  travel_rule_record_id?: string;
  created_at: string;
}

export interface ComplianceLogFilters {
  user_id?: string;
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
