import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Cache Invalidation', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('permission update reflects immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('permcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'permcachegroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    // Start with only eth_call
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Verify eth_getBalance is denied
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(false);

    // Update permissions to add eth_getBalance
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call', 'eth_getBalance'],
    });

    // Should immediately reflect the change
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);
  });

  test('role claim update reflects immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('claimcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'claimcachegroup');
    const role = await ctx.fixture.createRole(org.id, 'cachedrole', ['reader']);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Verify writer claim is missing
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['writer'],
    });
    expect(result.allowed).toBe(false);

    // Add writer claim to role
    await ctx.rbac.updateRole(org.id, role.id, {
      claims: ['reader', 'writer'],
    });

    // Should immediately have the new claim
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['writer'],
    });
    expect(result.allowed).toBe(true);
  });

  test('membership removal reflects immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('membershipcacheorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'group1');
    const group2 = await ctx.fixture.createGroup(org.id, 'group2');
    const role = await ctx.fixture.createReaderRole(org.id);

    // Group1 only has eth_call
    await ctx.rbac.setGroupPermissions(org.id, group1.id, {
      allow_methods: ['eth_call'],
    });

    // Group2 has eth_getBalance
    await ctx.rbac.setGroupPermissions(org.id, group2.id, {
      allow_methods: ['eth_getBalance'],
    });

    // User in both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
      roleId: role.id,
    });
    const membership2 = await ctx.fixture.addMembership(user.id, group2.id, role.id);

    // Verify user has eth_getBalance
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);

    // Remove membership from group2
    await ctx.rbac.deleteMembership(user.id, membership2.id);

    // eth_getBalance should now be denied
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(false);

    // eth_call should still work (from group1)
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);
  });

  test('user ban reflects immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('bancacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'bancachegroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Verify access works
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // Ban the user
    await ctx.rbac.updateUser(user.id, { banned: true });

    // Should immediately be denied
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('banned');
  });

  test('contract allowlist update reflects', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'contractcachegroup');
    const role = await ctx.fixture.createReaderRole(org.id);
    const contract1 = ctx.contractAddress().toLowerCase();
    const contract2 = ctx.contractAddress().toLowerCase();

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contract1],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Verify contract2 is denied
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract2,
    });
    expect(result.allowed).toBe(false);

    // Add contract2 to allowlist
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contract1, contract2],
    });

    // Should immediately allow contract2
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract2,
    });
    expect(result.allowed).toBe(true);
  });

  test('rate limit update reflects', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'ratelimitcachegroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 50,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Check initial rate limit
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.rate_limit_rps).toBe(50);

    // Update rate limit
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 100,
    });

    // Should immediately reflect new rate limit
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.rate_limit_rps).toBe(100);
  });

  test('KYC status update reflects', async ({ request }) => {
    const org = await ctx.fixture.createOrg('kyccacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'kyccachegroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // Start without KYC
      roleId: role.id,
    });

    // Verify denied without KYC
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('KYC');

    // Add KYC
    await ctx.rbac.updateUser(user.id, { kyc: true });

    // Should immediately be allowed
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);
  });

  test('adding new membership reflects', async ({ request }) => {
    const org = await ctx.fixture.createOrg('newmembershiporg');
    const group1 = await ctx.fixture.createGroup(org.id, 'newgroup1');
    const group2 = await ctx.fixture.createGroup(org.id, 'newgroup2');
    const role = await ctx.fixture.createReaderRole(org.id);

    // Group1 has eth_call
    await ctx.rbac.setGroupPermissions(org.id, group1.id, {
      allow_methods: ['eth_call'],
    });

    // Group2 has eth_getBalance
    await ctx.rbac.setGroupPermissions(org.id, group2.id, {
      allow_methods: ['eth_getBalance'],
    });

    // User starts in group1 only
    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
      roleId: role.id,
    });

    // Verify eth_getBalance is denied
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(false);

    // Add membership to group2
    await ctx.rbac.createMembership(user.id, {
      group_id: group2.id,
      role_id: role.id,
    });

    // Should immediately have access
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);
  });

  test('cache stats are available', async () => {
    const stats = await ctx.rbac.getCacheStats();

    expect(stats).toHaveProperty('entries');
    expect(stats).toHaveProperty('expired_pending');
    expect(stats).toHaveProperty('max_entries');
    expect(typeof stats.entries).toBe('number');
    expect(typeof stats.expired_pending).toBe('number');
    expect(typeof stats.max_entries).toBe('number');
  });
});
