import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

test.describe('RBAC Method Access Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('allows method in allowlist via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('methodalloworg');
    const group = await ctx.fixture.createGroup(org.id, 'methodallowgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  test('denies method NOT in allowlist via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('methoddenyorg');
    const group = await ctx.fixture.createGroup(org.id, 'methoddenygroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('method');
  });

  test('RPC request allowed for method in allowlist', async ({ request }) => {
    // Use the default org since RPC handler always uses default org
    const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcallowgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // Create user and add to the test group, removing default membership
    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_getBalance', [
      '0x0000000000000000000000000000000000000000',
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
    expect(body).toHaveProperty('result');
  });

  test('RPC request denied for method not in allowlist', async ({ request }) => {
    // Use the default org since RPC handler always uses default org
    const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcdenygroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_blockNumber'],
      default_claims: ['read', 'write'],
    });

    // Create user and add to the test group, removing default membership
    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_getBalance', [
      '0x0000000000000000000000000000000000000000',
      'latest',
    ]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('not allowed');
  });

  test('allows multiple methods in allowlist', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multimethodorg');
    const group = await ctx.fixture.createGroup(org.id, 'multimethodgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId'],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Test all methods
    for (const method of ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId']) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(true);
    }
  });

  test('denies when allowlist is empty', async ({ request }) => {
    const org = await ctx.fixture.createOrg('emptyalloworg');
    const group = await ctx.fixture.createGroup(org.id, 'emptyallowgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: [],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('method');
  });

  test('returns rate limits in access check result', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitorg');
    const group = await ctx.fixture.createGroup(org.id, 'ratelimitgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(true);
    expect(result.rate_limit_rps).toBe(100);
    expect(result.rate_limit_daily).toBe(10000);
  });
});
