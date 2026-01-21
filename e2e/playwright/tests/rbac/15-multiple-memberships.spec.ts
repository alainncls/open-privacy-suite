import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Multiple Memberships', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('methods UNIONed across memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('methodunionorg');

    // Two separate groups (siblings, not hierarchical)
    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A allows eth_call
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    // Group B allows eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // Create user and add to both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // User should have UNION: eth_call + eth_getBalance
    const resultCall = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(resultCall.allowed).toBe(true);

    const resultBalance = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(resultBalance.allowed).toBe(true);

    // Methods not in either group should still be denied
    const resultSend = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
    });
    expect(resultSend.allowed).toBe(false);
  });

  test('contracts UNIONed across memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractunionorg');

    // Create contracts
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A allows contract1
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: groupA.id,
      claims: ['read', 'write'],
    });

    // Group B allows contract2
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: groupB.id,
      claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // User should have access to both contracts
    for (const contract of [contract1, contract2]) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        target_address: contract.address,
        required_claims: ['read'],
      });
      expect(result.allowed).toBe(true);
    }
  });

  test('claims UNIONed across groups', async ({ request }) => {
    const org = await ctx.fixture.createOrg('claimunionorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A has read claim
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_sendTransaction'],
      default_claims: ['read'],
    });
    // Group B has write claim
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_sendTransaction'],
      default_claims: ['write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // User should have UNION of claims: read + write
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['read', 'write'],
    });
    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('read');
    expect(result.claims).toContain('write');
  });

  test('rate limits take MAX across memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitmaxorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A: 50 RPS
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 50,
      rate_limit_daily: 5000,
    });

    // Group B: 100 RPS
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(true);
    // Should get MAX rate limits
    expect(result.rate_limit_rps).toBe(100);
    expect(result.rate_limit_daily).toBe(10000);
  });

  test('multiple memberships with different depths', async ({ request }) => {
    const org = await ctx.fixture.createOrg('mixeddepthorg');

    // Hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Separate sibling group
    const sibling = await ctx.fixture.createGroup(org.id, 'sibling');

    // Root: A, B, C
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
    });

    // Child: A, B (intersection with root)
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // Sibling: D, E (completely different)
    await ctx.rbac.setGroupAccess(org.id, sibling.id, {
      allowed_methods: ['eth_chainId', 'eth_gasPrice'],
      default_claims: ['read', 'write'],
    });

    // User in both child and sibling
    const { user, did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, sibling.id);

    // From child (intersection of root): eth_call, eth_getBalance
    // From sibling: eth_chainId, eth_gasPrice
    // Total UNION: eth_call, eth_getBalance, eth_chainId, eth_gasPrice

    for (const method of ['eth_call', 'eth_getBalance', 'eth_chainId', 'eth_gasPrice']) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(true);
    }

    // eth_blockNumber removed in child hierarchy, not in sibling
    const resultBlock = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(resultBlock.allowed).toBe(false);
  });

  test('three group memberships combine correctly', async ({ request }) => {
    const org = await ctx.fixture.createOrg('threegrouporg');

    const group1 = await ctx.fixture.createGroup(org.id, 'group1');
    const group2 = await ctx.fixture.createGroup(org.id, 'group2');
    const group3 = await ctx.fixture.createGroup(org.id, 'group3');

    await ctx.rbac.setGroupAccess(org.id, group1.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 30,
    });
    await ctx.rbac.setGroupAccess(org.id, group2.id, {
      allowed_methods: ['eth_getBalance'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 60,
    });
    await ctx.rbac.setGroupAccess(org.id, group3.id, {
      allowed_methods: ['eth_blockNumber'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 90,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, group2.id);
    await ctx.fixture.addMembership(user.id, group3.id);

    // Should have all three methods
    for (const method of ['eth_call', 'eth_getBalance', 'eth_blockNumber']) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(true);
    }

    // Rate limit should be MAX
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.rate_limit_rps).toBe(90);
  });

  test('admin grants combine across memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('admincombineorg');

    // Create contracts
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);

    const group1 = await ctx.fixture.createGroup(org.id, 'group1');
    const group2 = await ctx.fixture.createGroup(org.id, 'group2');

    await ctx.rbac.setGroupAccess(org.id, group1.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: group1.id,
      claims: ['admin'],
    });

    await ctx.rbac.setGroupAccess(org.id, group2.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: group2.id,
      claims: ['admin'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, group2.id);

    // User should have admin on both contracts
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    expect(perms.contract_access[contract1.address]?.claims).toContain('admin');
    expect(perms.contract_access[contract2.address]?.claims).toContain('admin');
  });
});
