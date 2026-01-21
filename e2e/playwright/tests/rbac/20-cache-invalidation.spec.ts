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

    // Start with only eth_call
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify eth_getBalance is denied
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(false);

    // Update access to add eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // Should immediately reflect the change
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);
  });

  test('group claim update reflects immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('claimcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'claimcachegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_sendTransaction'],
      default_claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify write claim is missing
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['write'],
    });
    expect(result.allowed).toBe(false);

    // Add write claim to group
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_sendTransaction'],
      default_claims: ['read', 'write'],
    });

    // Should immediately have the new claim
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['write'],
    });
    expect(result.allowed).toBe(true);
  });

  test('membership removal reflects immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('membershipcacheorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'group1');
    const group2 = await ctx.fixture.createGroup(org.id, 'group2');

    // Group1 only has eth_call
    await ctx.rbac.setGroupAccess(org.id, group1.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    // Group2 has eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, group2.id, {
      allowed_methods: ['eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // User in both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
    });
    const membership2 = await ctx.fixture.addMembership(user.id, group2.id);

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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
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

  test('contract grant update reflects', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'contractcachegroup');

    // Create contracts
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });

    // Grant access to contract1 only
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify contract2 is denied
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract2.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(false);

    // Add grant for contract2
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    // Should immediately allow contract2
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract2.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(true);
  });

  test('rate limit update reflects', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitcacheorg');
    const group = await ctx.fixture.createGroup(org.id, 'ratelimitcachegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 50,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Check initial rate limit
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.rate_limit_rps).toBe(50);

    // Update rate limit
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // Start without KYC
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

    // Group1 has eth_call
    await ctx.rbac.setGroupAccess(org.id, group1.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    // Group2 has eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, group2.id, {
      allowed_methods: ['eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // User starts in group1 only
    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
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
