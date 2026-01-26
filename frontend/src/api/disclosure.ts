import axios from 'axios';
import type {
  DisclosureRequest,
  DisclosureGrant,
  DisclosureAccessEvent,
  DisclosureActivityLog,
  DisclosureActivitySummary,
  DisclosureReport,
  CreateDisclosureRequestInput,
  ApproveDisclosureResponse,
  RejectDisclosureInput,
  RevokeDisclosureInput,
  DisclosureReportType,
} from '../types/disclosure';

// Base API client for unauthenticated requests (admin endpoints)
const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Create an authenticated API client
const createAuthenticatedClient = (accessToken: string) => {
  return axios.create({
    baseURL: '/api',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });
};

// Create a disclosure token authenticated client
const createTokenClient = (disclosureToken: string) => {
  return axios.create({
    baseURL: '/api',
    headers: {
      'Content-Type': 'application/json',
      'X-Disclosure-Token': disclosureToken,
    },
  });
};

export const disclosureApi = {
  // ============================================
  // Admin endpoints (localhost-only)
  // ============================================
  admin: {
    // Create a new disclosure request
    createRequest: (input: CreateDisclosureRequestInput) => {
      // Transform frontend input to backend format
      const backendInput: Record<string, unknown> = {
        target_user_id: input.user_external_id, // user_external_id is actually the user UUID from dropdown
        requester_did: input.requester_did, // DID of auditor who will get access
        reason: input.purpose,
        legal_basis: input.legal_basis,
        scope: {
          methods: input.scope || [],
          disclosure_level: input.disclosure_level || 'pseudonymous',
        },
      };

      // Calculate expires_in_hours from valid_until if provided
      if (input.valid_until) {
        const now = new Date();
        const until = new Date(input.valid_until);
        const hoursUntil = Math.max(1, Math.ceil((until.getTime() - now.getTime()) / (1000 * 60 * 60)));
        backendInput.expires_in_hours = hoursUntil;
      }

      return api.post<DisclosureRequest>('/disclosure/requests', backendInput);
    },

    // List all disclosure requests
    listRequests: async (limit?: number, offset?: number) => {
      // Backend returns { request: {...}, target_did: "" }[] wrapper
      interface BackendRequestWithDetails {
        request: {
          id: string;
          target_user_id: string;
          org_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          reason: string;
          legal_basis?: string;
          status: string;
          requested_at: string;
          expires_at?: string;
          decided_at?: string;
          decided_by_user_id?: string;
          decision_reason?: string;
        };
        target_did: string;
      }

      const response = await api.get<BackendRequestWithDetails[]>('/disclosure/requests', {
        params: { limit, offset },
      });

      // Transform backend response to frontend format
      const transformedData: DisclosureRequest[] = (response.data || []).map((item) => ({
        id: item.request.id,
        user_id: item.request.target_user_id,
        requester_name: 'System', // Backend doesn't track requester name
        purpose: item.request.reason,
        scope: (item.request.scope?.methods || []) as DisclosureRequest['scope'],
        disclosure_level: (item.request.scope?.disclosure_level || 'pseudonymous') as DisclosureRequest['disclosure_level'],
        status: item.request.status as DisclosureRequest['status'],
        legal_basis: item.request.legal_basis,
        created_at: item.request.requested_at,
        updated_at: item.request.requested_at,
        valid_until: item.request.expires_at,
      }));

      return { ...response, data: transformedData };
    },

    // Get a specific disclosure request
    getRequest: (requestId: string) =>
      api.get<DisclosureRequest>(`/disclosure/requests/${requestId}`),
  },

  // ============================================
  // Grant access endpoints (require disclosure token)
  // ============================================
  grant: {
    // View activity logs for a grant
    getLogs: (grantId: string, token: string, limit?: number, offset?: number) =>
      createTokenClient(token).get<DisclosureActivityLog[]>(
        `/disclosure/grants/${grantId}/logs`,
        { params: { limit, offset } }
      ),

    // View activity summary for a grant
    getSummary: (grantId: string, token: string) =>
      createTokenClient(token).get<DisclosureActivitySummary>(
        `/disclosure/grants/${grantId}/summary`
      ),

    // Generate a report for a grant
    getReport: (grantId: string, token: string, reportType: DisclosureReportType) =>
      createTokenClient(token).get<DisclosureReport>(
        `/disclosure/grants/${grantId}/report/${reportType}`
      ),

    // View access audit trail for a grant
    getEvents: (grantId: string, token: string, limit?: number, offset?: number) =>
      createTokenClient(token).get<DisclosureAccessEvent[]>(
        `/disclosure/grants/${grantId}/events`,
        { params: { limit, offset } }
      ),
  },

  // ============================================
  // User endpoints (require JWT auth)
  // ============================================
  user: {
    // View pending disclosure requests for the current user
    getMyRequests: async (accessToken: string) => {
      // Backend returns { request: {...}, target_did: "" }[] wrapper
      interface BackendRequestWithDetails {
        request: {
          id: string;
          target_user_id: string;
          org_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          reason: string;
          legal_basis?: string;
          status: string;
          requested_at: string;
          expires_at?: string;
          decided_at?: string;
          decided_by_user_id?: string;
          decision_reason?: string;
        };
        target_did: string;
      }

      const response = await createAuthenticatedClient(accessToken).get<BackendRequestWithDetails[]>(
        '/me/disclosure/requests'
      );

      // Transform backend response to frontend format
      const transformedData: DisclosureRequest[] = (response.data || []).map((item) => ({
        id: item.request.id,
        user_id: item.request.target_user_id,
        requester_name: 'Compliance Request', // Backend doesn't track requester name
        purpose: item.request.reason,
        scope: (item.request.scope?.methods || []) as DisclosureRequest['scope'],
        disclosure_level: (item.request.scope?.disclosure_level || 'pseudonymous') as DisclosureRequest['disclosure_level'],
        status: item.request.status as DisclosureRequest['status'],
        legal_basis: item.request.legal_basis,
        created_at: item.request.requested_at,
        updated_at: item.request.requested_at,
        valid_until: item.request.expires_at,
      }));

      return { ...response, data: transformedData };
    },

    // Approve a disclosure request
    approveRequest: (accessToken: string, requestId: string) =>
      createAuthenticatedClient(accessToken).post<ApproveDisclosureResponse>(
        `/me/disclosure/requests/${requestId}/approve`
      ),

    // Reject a disclosure request
    rejectRequest: (accessToken: string, requestId: string, input?: RejectDisclosureInput) =>
      createAuthenticatedClient(accessToken).post<DisclosureRequest>(
        `/me/disclosure/requests/${requestId}/reject`,
        input || {}
      ),

    // Revoke a previously approved grant
    revokeRequest: (accessToken: string, requestId: string, input?: RevokeDisclosureInput) =>
      createAuthenticatedClient(accessToken).post<DisclosureRequest>(
        `/me/disclosure/requests/${requestId}/revoke`,
        input || {}
      ),

    // View active grants on user's data
    getMyGrants: async (accessToken: string) => {
      // Backend returns GrantWithRequest[] wrapper
      interface BackendGrantWithRequest {
        grant: {
          id: string;
          request_id: string;
          scope: { methods?: string[]; addresses?: string[] };
          granted_at: string;
          expires_at: string;
          revoked_at?: string;
          revoked_reason?: string;
        };
        request: {
          id: string;
          target_user_id: string;
          reason: string;
          legal_basis?: string;
          status: string;
        };
      }

      const response = await createAuthenticatedClient(accessToken).get<BackendGrantWithRequest[]>(
        '/me/disclosure/grants'
      );

      // Transform backend response to frontend format
      const transformedData: DisclosureGrant[] = (response.data || []).map((item) => ({
        id: item.grant.id,
        request_id: item.grant.request_id,
        user_id: item.request.target_user_id,
        token_hash: '', // Not exposed to frontend
        scope: (item.grant.scope?.methods || []) as DisclosureGrant['scope'],
        valid_from: item.grant.granted_at,
        valid_until: item.grant.expires_at,
        revoked_at: item.grant.revoked_at,
        revoke_reason: item.grant.revoked_reason,
        created_at: item.grant.granted_at,
        updated_at: item.grant.granted_at,
      }));

      return { ...response, data: transformedData };
    },
  },
};

export default disclosureApi;
