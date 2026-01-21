import { http, HttpResponse } from 'msw';
import type {
  AuthRequestResponse,
  AuthTokenResponse,
} from '@/api/auth';
import type {
  Organization,
  Group,
  User,
  Contract,
  GroupAccess,
  EffectivePermissions,
  UserMembership,
  MembershipWithDetails,
} from '@/types/rbac';

// Mock data fixtures
export const mockAuthRequest: AuthRequestResponse = {
  session_id: 'test-session-123',
  auth_request: {
    id: 'auth-req-456',
    typ: 'application/iden3comm-plain-json',
    type: 'https://iden3-communication.io/authorization/1.0/request',
    body: {
      callbackUrl: 'http://localhost:8080/api/auth/callback',
      reason: 'Privacy Proxy Authentication',
      scope: [],
    },
    from: 'did:polygonid:polygon:main:verifier123',
  },
};

export const mockTokenResponse: AuthTokenResponse = {
  access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bWFpbjp1c2VyMTIzIiwiZXhwIjoxNzA0MDY3MjAwfQ.test',
  refresh_token: 'refresh-token-abc123',
  token_type: 'Bearer',
  expires_in: 3600,
};

export const mockOrganization: Organization = {
  id: 'org-1',
  slug: 'test-org',
  name: 'Test Organization',
  settings: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockGroup: Group = {
  id: 'group-1',
  org_id: 'org-1',
  parent_id: null,
  slug: 'root',
  name: 'Root Group',
  description: 'The root group',
  depth: 0,
  path: 'root',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockUser: User = {
  id: 'user-1',
  external_id: 'did:polygonid:polygon:main:user123',
  kyc: true,
  banned: false,
  note: '',
  metadata: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockContract: Contract = {
  id: 'contract-1',
  address: '0x1234567890123456789012345678901234567890',
  org_id: 'org-1',
  name: 'Test Contract',
  deployed_by_user_id: null,
  deployed_at: null,
  metadata: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockGroupAccess: GroupAccess = {
  id: 'access-1',
  group_id: 'group-1',
  allowed_methods: ['eth_call', 'eth_getBalance'],
  default_claims: ['read'],
  rate_limit_rps: 100,
  rate_limit_daily: 10000,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockMembership: UserMembership = {
  id: 'membership-1',
  user_id: 'user-1',
  group_id: 'group-1',
  source: 'admin',
  zk_credential_ref: '',
  expires_at: null,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockMembershipWithDetails: MembershipWithDetails = {
  membership: mockMembership,
  group: mockGroup,
};

export const mockEffectivePermissions: EffectivePermissions = {
  id: 'eff-perms-1',
  user_id: 'user-1',
  org_id: 'org-1',
  allowed_methods: ['eth_call', 'eth_getBalance', 'eth_sendTransaction'],
  contract_access: {},
  default_claims: ['read', 'write'],
  rate_limit_rps: 100,
  rate_limit_daily: 10000,
  computed_at: '2024-01-01T00:00:00Z',
  expires_at: '2024-01-02T00:00:00Z',
};

// Session state for polling simulation
let sessionCompleted = false;
let sessionTokens: AuthTokenResponse | null = null;

export function setSessionCompleted(completed: boolean, tokens?: AuthTokenResponse) {
  sessionCompleted = completed;
  sessionTokens = tokens || null;
}

export function resetSessionState() {
  sessionCompleted = false;
  sessionTokens = null;
}

// MSW handlers
export const handlers = [
  // Auth endpoints
  http.post('/api/auth/request', () => {
    return HttpResponse.json(mockAuthRequest);
  }),

  http.post('/api/auth/verify', async ({ request }) => {
    const body = await request.json() as { session_id: string; jwz_token: string };
    if (body.jwz_token.startsWith('mock.')) {
      return HttpResponse.json(mockTokenResponse);
    }
    return HttpResponse.json({ error: 'Invalid token' }, { status: 401 });
  }),

  http.get('/api/auth/session/:sessionId/status', () => {
    if (sessionCompleted && sessionTokens) {
      return HttpResponse.json({ completed: true, tokens: sessionTokens });
    }
    return HttpResponse.json({ completed: false });
  }),

  http.post('/api/refresh', async ({ request }) => {
    const body = await request.json() as { refresh_token: string };
    if (body.refresh_token) {
      return HttpResponse.json({
        ...mockTokenResponse,
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
      });
    }
    return HttpResponse.json({ error: 'Invalid refresh token' }, { status: 401 });
  }),

  http.post('/api/revoke', () => {
    return HttpResponse.json({ message: 'Token revoked' });
  }),

  // ETH Link endpoints
  http.post('/api/eth/link/challenge', () => {
    return HttpResponse.json({
      nonce: 'test-nonce-123',
      message: 'Link Ethereum address to DID\n\nDID: did:test\nNonce: test-nonce-123',
    });
  }),

  http.post('/api/eth/link/verify', async ({ request }) => {
    const body = await request.json() as { nonce: string; address: string; signature: string };
    return HttpResponse.json({
      message: 'Address linked successfully',
      address: body.address,
    });
  }),

  http.get('/api/eth/addresses', () => {
    return HttpResponse.json({
      addresses: [
        { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-01T00:00:00Z' },
      ],
    });
  }),

  http.delete('/api/eth/addresses/:address', () => {
    return HttpResponse.json({ message: 'Address unlinked' });
  }),

  // Organization endpoints
  http.get('/api/orgs', () => {
    return HttpResponse.json([mockOrganization]);
  }),

  http.get('/api/orgs/:orgId', ({ params }) => {
    if (params.orgId === 'org-1') {
      return HttpResponse.json(mockOrganization);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('/api/orgs', async ({ request }) => {
    const body = await request.json() as { slug: string; name: string };
    return HttpResponse.json({
      ...mockOrganization,
      id: 'org-new',
      slug: body.slug,
      name: body.name,
    });
  }),

  http.put('/api/orgs/:orgId', async ({ request, params }) => {
    const body = await request.json() as { slug?: string; name?: string };
    return HttpResponse.json({
      ...mockOrganization,
      id: params.orgId as string,
      ...(body.slug && { slug: body.slug }),
      ...(body.name && { name: body.name }),
    });
  }),

  http.delete('/api/orgs/:orgId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Group endpoints
  http.get('/api/orgs/:orgId/groups', () => {
    return HttpResponse.json([mockGroup]);
  }),

  http.get('/api/orgs/:orgId/groups/:groupId', ({ params }) => {
    if (params.groupId === 'group-1') {
      return HttpResponse.json(mockGroup);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('/api/orgs/:orgId/groups', async ({ request, params }) => {
    const body = await request.json() as { slug: string; name: string; description?: string };
    return HttpResponse.json({
      ...mockGroup,
      id: 'group-new',
      org_id: params.orgId as string,
      slug: body.slug,
      name: body.name,
      description: body.description || '',
    });
  }),

  http.put('/api/orgs/:orgId/groups/:groupId', async ({ request, params }) => {
    const body = await request.json() as { name?: string; description?: string };
    return HttpResponse.json({
      ...mockGroup,
      id: params.groupId as string,
      ...(body.name && { name: body.name }),
      ...(body.description !== undefined && { description: body.description }),
    });
  }),

  http.delete('/api/orgs/:orgId/groups/:groupId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  http.get('/api/orgs/:orgId/groups/:groupId/access', () => {
    return HttpResponse.json(mockGroupAccess);
  }),

  http.put('/api/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
    const body = await request.json() as {
      allowed_methods?: string[];
      default_claims?: string[];
    };
    return HttpResponse.json({
      ...mockGroupAccess,
      ...(body.allowed_methods && { allowed_methods: body.allowed_methods }),
      ...(body.default_claims && { default_claims: body.default_claims }),
    });
  }),

  // User endpoints
  http.get('/api/users', () => {
    return HttpResponse.json([mockUser]);
  }),

  http.get('/api/users/:userId', ({ params }) => {
    if (params.userId === 'user-1') {
      return HttpResponse.json(mockUser);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.put('/api/users/:userId', async ({ request, params }) => {
    const body = await request.json() as { kyc?: boolean; banned?: boolean; note?: string };
    return HttpResponse.json({
      ...mockUser,
      id: params.userId as string,
      ...(body.kyc !== undefined && { kyc: body.kyc }),
      ...(body.banned !== undefined && { banned: body.banned }),
      ...(body.note !== undefined && { note: body.note }),
    });
  }),

  http.get('/api/users/:userId/memberships', () => {
    return HttpResponse.json([mockMembershipWithDetails]);
  }),

  http.post('/api/users/:userId/memberships', async ({ request, params }) => {
    const body = await request.json() as { group_id: string };
    return HttpResponse.json({
      ...mockMembership,
      id: 'membership-new',
      user_id: params.userId as string,
      group_id: body.group_id,
    });
  }),

  http.delete('/api/users/:userId/memberships/:membershipId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  http.get('/api/users/:userId/effective-permissions', () => {
    return HttpResponse.json(mockEffectivePermissions);
  }),

  // Contract endpoints
  http.get('/api/orgs/:orgId/contracts', () => {
    return HttpResponse.json([mockContract]);
  }),

  http.post('/api/orgs/:orgId/contracts', async ({ request, params }) => {
    const body = await request.json() as {
      address: string;
      name?: string;
      metadata?: Record<string, unknown>;
    };
    return HttpResponse.json({
      ...mockContract,
      id: 'contract-new',
      org_id: params.orgId as string,
      address: body.address,
      name: body.name || null,
      metadata: body.metadata || {},
    });
  }),

  http.put('/api/orgs/:orgId/contracts/:address', async ({ request, params }) => {
    const body = await request.json() as {
      name?: string;
      metadata?: Record<string, unknown>;
    };
    return HttpResponse.json({
      ...mockContract,
      address: params.address as string,
      ...(body.name && { name: body.name }),
      ...(body.metadata && { metadata: body.metadata }),
    });
  }),

  http.delete('/api/orgs/:orgId/contracts/:address', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Utility endpoints
  http.post('/api/access/check', async () => {
    return HttpResponse.json({
      allowed: true,
      reason: 'Access granted',
      rate_limit_rps: 100,
      claims: ['read'],
    });
  }),

  http.get('/api/cache/stats', () => {
    return HttpResponse.json({
      hits: 100,
      misses: 10,
      size: 50,
    });
  }),
];
