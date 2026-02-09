import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

test.describe('RBAC User Status Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('banned user is denied via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('bannedorg');
    const group = await ctx.fixture.createGroup(org.id, 'bannedgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      banned: true, // User is banned
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('banned');
  });

  test('banned user denied via RPC request', async ({ request }) => {
    const org = await ctx.fixture.createOrg('bannedrpcorg');
    const group = await ctx.fixture.createGroup(org.id, 'bannedrpcgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read', 'write'],
    });

    const { token, user } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Ban the user after they have a token
    await ctx.rbac.updateUser(user.id, { banned: true });

    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('banned');
  });

  test('non-KYC user is denied via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('nokycorg');
    const group = await ctx.fixture.createGroup(org.id, 'nokycgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // No KYC
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('KYC');
  });

  test('non-KYC user denied via RPC request', async ({ request }) => {
    const org = await ctx.fixture.createOrg('nokycrpcorg');
    const group = await ctx.fixture.createGroup(org.id, 'nokycrpcgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read', 'write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // No KYC
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('KYC');
  });

  test('KYC update enables access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('kycupdateorg');
    const group = await ctx.fixture.createGroup(org.id, 'kycupdategroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read', 'write'],
    });

    const { user, did, token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // Start without KYC
    });

    // First request should fail
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('KYC');

    // Update KYC status
    await ctx.rbac.updateUser(user.id, { kyc: true });

    // Second request should succeed
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(result.allowed).toBe(true);
  });

  test('unbanning user restores access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('unbanorg');
    const group = await ctx.fixture.createGroup(org.id, 'unbangroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      banned: true, // Start banned
    });

    // First request should fail
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('banned');

    // Unban the user
    await ctx.rbac.updateUser(user.id, { banned: false });

    // Second request should succeed
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(result.allowed).toBe(true);
  });

  test('user not found returns denied', async () => {
    const org = await ctx.fixture.createOrg('notfoundorg');

    const result = await ctx.rbac.checkAccess({
      user_external_id: 'did:privado:nonexistent12345',
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('not found');
  });

  test('banned takes precedence over other checks', async ({ request }) => {
    const org = await ctx.fixture.createOrg('bannedprecedenceorg');
    const group = await ctx.fixture.createGroup(org.id, 'bannedprecedencegroup');

    // Even with full permissions
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'deploy', 'admin', 'upgrade'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      banned: true, // Banned overrides everything
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    // Should be denied due to ban, even though user has all other permissions
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('banned');
  });

  test('KYC check happens after ban check', async ({ request }) => {
    const org = await ctx.fixture.createOrg('orderedcheckorg');
    const group = await ctx.fixture.createGroup(org.id, 'orderedcheckgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // No KYC
      banned: true, // Also banned
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    // Should report banned first (checked before KYC)
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('banned');
  });
});
