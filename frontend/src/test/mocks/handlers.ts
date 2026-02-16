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
  ContractGrant,
  GroupAccess,
  EffectivePermissions,
  UserMembership,
  MembershipWithDetails,
  Claim,
  PreregisteredAddress,
  PreregisterInput,
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
  claims: ['read'],
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
  contract_access: {
    '0x1234567890123456789012345678901234567890': {
      claims: ['read', 'write'] as Claim[],
      functions: null,
    },
  },
  claims: ['read', 'write'] as Claim[],
  rate_limit_rps: 100,
  rate_limit_daily: 10000,
  computed_at: '2024-01-01T00:00:00Z',
  expires_at: '2024-01-02T00:00:00Z',
};

// Linked ETH addresses for user
export const mockLinkedAddresses = [
  { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-01T00:00:00Z' },
  { address: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd', verified_at: '2024-01-15T00:00:00Z' },
];

// Contract grants linking groups to contracts
// Claims are inherited from the group's GroupAccess.claims
export const mockContractGrant: ContractGrant = {
  id: 'grant-1',
  contract_id: 'contract-1',
  group_id: 'group-1',
  functions: null,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

// Additional user for multi-user testing
export const mockUser2: User = {
  id: 'user-2',
  external_id: 'did:polygonid:polygon:main:user456',
  kyc: false,
  banned: false,
  note: 'Secondary test user',
  metadata: {},
  created_at: '2024-01-10T00:00:00Z',
  updated_at: '2024-01-10T00:00:00Z',
};

// Additional organization for multi-org testing
export const mockOrganization2: Organization = {
  id: 'org-2',
  slug: 'other-org',
  name: 'Other Organization',
  settings: {},
  created_at: '2024-01-15T00:00:00Z',
  updated_at: '2024-01-15T00:00:00Z',
};

// Additional group for nested hierarchy testing
export const mockChildGroup: Group = {
  id: 'group-2',
  org_id: 'org-1',
  parent_id: 'group-1',
  slug: 'engineering',
  name: 'Engineering',
  description: 'Engineering team',
  depth: 1,
  path: 'root.engineering',
  created_at: '2024-01-02T00:00:00Z',
  updated_at: '2024-01-02T00:00:00Z',
};

// Second membership for multi-membership testing
export const mockMembership2: UserMembership = {
  id: 'membership-2',
  user_id: 'user-1',
  group_id: 'group-2',
  source: 'zk_attested',
  zk_credential_ref: 'cred:polygonid:credential:12345',
  expires_at: '2025-01-01T00:00:00Z',
  created_at: '2024-01-10T00:00:00Z',
  updated_at: '2024-01-10T00:00:00Z',
};

export const mockMembershipWithDetails2: MembershipWithDetails = {
  membership: mockMembership2,
  group: mockChildGroup,
};

// Preregistered addresses for CREATE3 testing
export const mockPreregisteredAddress: PreregisteredAddress = {
  id: 'preregistered-1',
  org_id: 'org-1',
  address: '0xabcdef1234567890abcdef1234567890abcdef12',
  factory: '0x1234567890123456789012345678901234567890',
  salt: '0x6d79617070000000000000000000000000000000000000000000000000000000',
  note: 'Test preregistered address',
  created_at: '2024-01-01T00:00:00Z',
  used_at: null,
};

export const mockPreregisteredAddressUsed: PreregisteredAddress = {
  id: 'preregistered-2',
  org_id: 'org-1',
  address: '0xdeadbeef1234567890deadbeef1234567890dead',
  factory: '0x1234567890123456789012345678901234567890',
  salt: '0x6d79617070000000000000000000000000000000000000000000000000000001',
  note: 'Used preregistered address',
  created_at: '2024-01-01T00:00:00Z',
  used_at: '2024-01-15T00:00:00Z',
};

export const mockPreregisteredAddresses: PreregisteredAddress[] = [
  mockPreregisteredAddress,
  mockPreregisteredAddressUsed,
];

// CREATE3 factory for dev mode testing
export const mockCreate3Factory = {
  address: '0xfactory1234567890factory1234567890factory',
  deployed: true,
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
  http.post('/api/v1/auth/request', () => {
    return HttpResponse.json(mockAuthRequest);
  }),

  http.post('/api/v1/auth/verify', async ({ request }) => {
    const body = await request.json() as { session_id: string; jwz_token: string };
    if (body.jwz_token.startsWith('mock.')) {
      return HttpResponse.json(mockTokenResponse);
    }
    return HttpResponse.json({ error: 'Invalid token' }, { status: 401 });
  }),

  http.get('/api/v1/auth/session/:sessionId/status', () => {
    if (sessionCompleted && sessionTokens) {
      return HttpResponse.json({ completed: true, tokens: sessionTokens });
    }
    return HttpResponse.json({ completed: false });
  }),

  http.post('/api/v1/refresh', async ({ request }) => {
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

  http.post('/api/v1/revoke', () => {
    return HttpResponse.json({ message: 'Token revoked' });
  }),

  // ETH Link endpoints
  http.post('/api/v1/eth/link/challenge', () => {
    return HttpResponse.json({
      nonce: 'test-nonce-123',
      message: 'Link Ethereum address to DID\n\nDID: did:test\nNonce: test-nonce-123',
    });
  }),

  http.post('/api/v1/eth/link/verify', async ({ request }) => {
    const body = await request.json() as { nonce: string; address: string; signature: string };
    return HttpResponse.json({
      message: 'Address linked successfully',
      address: body.address,
    });
  }),

  http.get('/api/v1/eth/addresses', () => {
    return HttpResponse.json({
      addresses: [
        { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-01T00:00:00Z' },
      ],
    });
  }),

  http.delete('/api/v1/eth/addresses/:address', () => {
    return HttpResponse.json({ message: 'Address unlinked' });
  }),

  // Organization endpoints
  http.get('/api/v1/orgs', () => {
    return HttpResponse.json({ data: [mockOrganization], total: 1, limit: 25, offset: 0 });
  }),

  http.get('/api/v1/orgs/:orgId', ({ params }) => {
    if (params.orgId === 'org-1') {
      return HttpResponse.json(mockOrganization);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('/api/v1/orgs', async ({ request }) => {
    const body = await request.json() as { slug: string; name: string };
    return HttpResponse.json({
      ...mockOrganization,
      id: 'org-new',
      slug: body.slug,
      name: body.name,
    });
  }),

  http.put('/api/v1/orgs/:orgId', async ({ request, params }) => {
    const body = await request.json() as { slug?: string; name?: string };
    return HttpResponse.json({
      ...mockOrganization,
      id: params.orgId as string,
      ...(body.slug && { slug: body.slug }),
      ...(body.name && { name: body.name }),
    });
  }),

  http.delete('/api/v1/orgs/:orgId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Group endpoints
  http.get('/api/v1/orgs/:orgId/groups', () => {
    return HttpResponse.json({ data: [{ group: mockGroup, access: mockGroupAccess }], total: 1, limit: 50, offset: 0 });
  }),

  http.get('/api/v1/orgs/:orgId/groups/:groupId', ({ params }) => {
    if (params.groupId === 'group-1') {
      return HttpResponse.json(mockGroup);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('/api/v1/orgs/:orgId/groups', async ({ request, params }) => {
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

  http.put('/api/v1/orgs/:orgId/groups/:groupId', async ({ request, params }) => {
    const body = await request.json() as { name?: string; description?: string };
    return HttpResponse.json({
      ...mockGroup,
      id: params.groupId as string,
      ...(body.name && { name: body.name }),
      ...(body.description !== undefined && { description: body.description }),
    });
  }),

  http.delete('/api/v1/orgs/:orgId/groups/:groupId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
    return HttpResponse.json(mockGroupAccess);
  }),

  http.put('/api/v1/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
    const body = await request.json() as {
      allowed_methods?: string[];
      claims?: string[];
    };
    return HttpResponse.json({
      ...mockGroupAccess,
      ...(body.allowed_methods && { allowed_methods: body.allowed_methods }),
      ...(body.claims && { claims: body.claims }),
    });
  }),

  // User endpoints
  http.get('/api/v1/users', () => {
    return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
  }),

  http.get('/api/v1/users/:userId', ({ params }) => {
    if (params.userId === 'user-1') {
      return HttpResponse.json(mockUser);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.put('/api/v1/users/:userId', async ({ request, params }) => {
    const body = await request.json() as { kyc?: boolean; banned?: boolean; note?: string };
    return HttpResponse.json({
      ...mockUser,
      id: params.userId as string,
      ...(body.kyc !== undefined && { kyc: body.kyc }),
      ...(body.banned !== undefined && { banned: body.banned }),
      ...(body.note !== undefined && { note: body.note }),
    });
  }),

  http.get('/api/v1/users/:userId/memberships', () => {
    return HttpResponse.json([mockMembershipWithDetails]);
  }),

  http.post('/api/v1/users/:userId/memberships', async ({ request, params }) => {
    const body = await request.json() as { group_id: string };
    return HttpResponse.json({
      ...mockMembership,
      id: 'membership-new',
      user_id: params.userId as string,
      group_id: body.group_id,
    });
  }),

  http.delete('/api/v1/users/:userId/memberships/:membershipId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  http.get('/api/v1/users/:userId/effective-permissions', () => {
    return HttpResponse.json(mockEffectivePermissions);
  }),

  // Linked addresses endpoint
  http.get('/api/v1/users/:userId/linked-addresses', () => {
    return HttpResponse.json({ addresses: mockLinkedAddresses });
  }),

  // Contract endpoints
  http.get('/api/v1/orgs/:orgId/contracts', () => {
    return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
  }),

  http.post('/api/v1/orgs/:orgId/contracts', async ({ request, params }) => {
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

  http.put('/api/v1/orgs/:orgId/contracts/:address', async ({ request, params }) => {
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

  http.delete('/api/v1/orgs/:orgId/contracts/:address', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Contract grant endpoints
  http.get('/api/v1/orgs/:orgId/contracts/:address/grants', () => {
    return HttpResponse.json([mockContractGrant]);
  }),

  http.post('/api/v1/orgs/:orgId/contracts/:address/grants', async ({ request, params }) => {
    const body = await request.json() as {
      group_id: string;
      functions?: string[] | null;
    };
    return HttpResponse.json({
      ...mockContractGrant,
      id: 'grant-new',
      contract_id: params.address as string,
      group_id: body.group_id,
      functions: body.functions ?? null,
    });
  }),

  http.put('/api/v1/orgs/:orgId/contracts/:address/grants/:groupId', async ({ request, params }) => {
    const body = await request.json() as {
      functions?: string[] | null;
    };
    return HttpResponse.json({
      ...mockContractGrant,
      group_id: params.groupId as string,
      ...(body.functions !== undefined && { functions: body.functions }),
    });
  }),

  http.delete('/api/v1/orgs/:orgId/contracts/:address/grants/:groupId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Contract lookup by address (cross-org)
  http.get('/api/v1/contracts/by-address/:address', ({ params }) => {
    if (params.address === mockContract.address) {
      return HttpResponse.json({
        contract: mockContract,
        organization: mockOrganization,
        grants: [{
          grant: mockContractGrant,
          group: mockGroup,
          access: mockGroupAccess,
        }],
      });
    }
    return HttpResponse.json({ error: 'contract not found' }, { status: 404 });
  }),

  // Utility endpoints
  http.post('/api/v1/access/check', async () => {
    return HttpResponse.json({
      allowed: true,
      reason: 'Access granted',
      rate_limit_rps: 100,
      claims: ['read'],
    });
  }),

  http.get('/api/v1/cache/stats', () => {
    return HttpResponse.json({
      hits: 100,
      misses: 10,
      size: 50,
    });
  }),

  // Preregistered addresses endpoints
  http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
    return HttpResponse.json(mockPreregisteredAddresses);
  }),

  http.post('/api/v1/orgs/:orgId/addresses/preregister', async ({ request, params }) => {
    const body = await request.json() as PreregisterInput;
    // Generate mock addresses based on input
    const addresses: PreregisteredAddress[] = [];
    for (let i = 0; i < body.count; i++) {
      addresses.push({
        id: `preregistered-new-${i}`,
        org_id: params.orgId as string,
        address: `0x${(i + 1).toString(16).padStart(40, 'a')}`,
        factory: body.factory,
        salt: `${body.salt_prefix}${i.toString(16).padStart(8, '0')}`,
        note: body.note || undefined,
        created_at: new Date().toISOString(),
        used_at: null,
      });
    }
    return HttpResponse.json({ addresses });
  }),

  http.delete('/api/v1/orgs/:orgId/addresses/preregistered/:address', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Org config endpoints for CREATE3 factory
  http.get('/api/v1/orgs/:orgId/config/create3', () => {
    return HttpResponse.json({
      factory: '0x1234567890123456789012345678901234567890',
      configured: true,
    });
  }),

  http.put('/api/v1/orgs/:orgId/config/create3', async ({ request }) => {
    const body = await request.json() as { factory: string };
    return HttpResponse.json({
      factory: body.factory,
      configured: true,
    });
  }),

  // Dev endpoints for CREATE3 factory
  http.get('/api/v1/dev/create3-factory', () => {
    return HttpResponse.json(mockCreate3Factory);
  }),

  http.post('/api/v1/dev/create3-factory', () => {
    return HttpResponse.json({
      address: '0xfactory1234567890factory1234567890factory',
      deployed: true,
    });
  }),
];
