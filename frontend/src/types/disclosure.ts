// Disclosure TypeScript types mirroring backend models

export type DisclosureRequestStatus = 'pending' | 'approved' | 'rejected' | 'revoked' | 'expired';

export type DisclosureScope = 'activity_logs' | 'transaction_history' | 'full_disclosure';

export type DisclosureReportType = 'activity_summary' | 'sanctions_check' | 'compliance_report';

// DisclosureLevel controls how much address detail is revealed
export type DisclosureLevel = 'full' | 'pseudonymous' | 'redacted';

export interface DisclosureRequest {
  id: string;
  user_id: string;
  requester_name: string;
  requester_org?: string;
  requester_did?: string;
  purpose: string;
  scope: DisclosureScope[];
  disclosure_level?: DisclosureLevel;
  status: DisclosureRequestStatus;
  valid_from?: string;
  valid_until?: string;
  request_reference?: string;
  legal_basis?: string;
  created_at: string;
  updated_at: string;
  decided_at?: string;
  decision_reason?: string;
  active_grant_id?: string;
}

export interface DisclosureGrant {
  id: string;
  request_id: string;
  user_id: string;
  token_hash: string;
  scope: DisclosureScope[];
  disclosure_level?: DisclosureLevel;
  valid_from: string;
  valid_until: string;
  revoked_at?: string;
  revoke_reason?: string;
  requester_did?: string;
  reason?: string;
  created_at: string;
  updated_at: string;
}

export interface DisclosureAccessEvent {
  id: string;
  grant_id: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
}

export interface DisclosureActivityLog {
  id: string;
  user_id: string;
  method: string;
  target_address?: string;
  status: string;
  ip_address?: string;
  timestamp: string;
}

export interface DisclosureActivitySummary {
  total_requests: number;
  methods: Record<string, number>;
  addresses_accessed: string[];
  first_activity?: string;
  last_activity?: string;
}

export interface DisclosureReport {
  type: DisclosureReportType;
  generated_at: string;
  data: unknown;
}

// Input types
export interface CreateDisclosureRequestInput {
  user_external_id: string;
  requester_name: string;
  requester_org?: string;
  requester_did?: string; // DID of auditor who will get access (for block explorer integration)
  purpose: string;
  scope: DisclosureScope[];
  disclosure_level: DisclosureLevel;
  valid_from?: string;
  valid_until?: string;
  request_reference?: string;
  legal_basis?: string;
}

export interface ApproveDisclosureResponse {
  grant: DisclosureGrant;
  message: string;
}

export interface RejectDisclosureInput {
  reason?: string;
}

export interface RevokeDisclosureInput {
  reason?: string;
}

// Scope labels for display
export const SCOPE_LABELS: Record<DisclosureScope, string> = {
  activity_logs: 'Activity Logs',
  transaction_history: 'Transaction History',
  full_disclosure: 'Full Disclosure',
};

// Scope descriptions
export const SCOPE_DESCRIPTIONS: Record<DisclosureScope, string> = {
  activity_logs: 'Access to your RPC request logs and method usage',
  transaction_history: 'Access to your transaction history and wallet interactions',
  full_disclosure: 'Complete access to all activity data',
};

// Status labels for display
export const STATUS_LABELS: Record<DisclosureRequestStatus, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  revoked: 'Revoked',
  expired: 'Expired',
};

// Status badge variants
export const STATUS_VARIANTS: Record<DisclosureRequestStatus, 'warning' | 'success' | 'destructive' | 'secondary'> = {
  pending: 'warning',
  approved: 'success',
  rejected: 'destructive',
  revoked: 'destructive',
  expired: 'secondary',
};

// Report type labels
export const REPORT_TYPE_LABELS: Record<DisclosureReportType, string> = {
  activity_summary: 'Activity Summary',
  sanctions_check: 'Sanctions Check',
  compliance_report: 'Compliance Report',
};

// All available scopes
export const ALL_SCOPES: DisclosureScope[] = ['activity_logs', 'transaction_history', 'full_disclosure'];

// All report types
export const ALL_REPORT_TYPES: DisclosureReportType[] = ['activity_summary', 'sanctions_check', 'compliance_report'];

// Disclosure level labels
export const DISCLOSURE_LEVEL_LABELS: Record<DisclosureLevel, string> = {
  full: 'Full (Show Real Addresses)',
  pseudonymous: 'Pseudonymous (Show Aliases)',
  redacted: 'Redacted (Hide Addresses)',
};

// Disclosure level descriptions
export const DISCLOSURE_LEVEL_DESCRIPTIONS: Record<DisclosureLevel, string> = {
  full: 'Auditor sees real ETH addresses - for regulatory subpoenas, law enforcement',
  pseudonymous: 'Auditor sees consistent pseudonyms (Address-A, Address-B) - for compliance audits',
  redacted: 'All addresses hidden, only aggregate stats visible - for minimal disclosure',
};

// All disclosure levels
export const ALL_DISCLOSURE_LEVELS: DisclosureLevel[] = ['full', 'pseudonymous', 'redacted'];

// Filter for listing disclosures
export interface DisclosureFilter {
  status?: DisclosureRequestStatus;
  target_user_id?: string;
  requester_did?: string;
  disclosure_level?: DisclosureLevel;
  date_from?: string;
  date_to?: string;
  limit?: number;
  offset?: number;
}

// Result types for filtered listing
export interface DisclosureListResult {
  requests: DisclosureRequest[];
  total: number;
  limit: number;
  offset: number;
}

export interface GrantListResult {
  grants: DisclosureGrant[];
  total: number;
  limit: number;
  offset: number;
}
