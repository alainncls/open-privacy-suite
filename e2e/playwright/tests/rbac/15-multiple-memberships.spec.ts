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
    await ctx.rbac.setGroupPermissions(org.id, groupA.id, {
      allow_methods: ['eth_call'],
    });

    // Group B allows eth_getBalance
    await ctx.rbac.setGroupPermissions(org.id, groupB.id, {
      allow_methods: ['eth_getBalance'],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    // Create user and add to both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
      roleId: role.id,
    });
    await ctx.fixture.addMembership(user.id, groupB.id, role.id);

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
    const contract1 = ctx.contractAddress().toLowerCase();
    const contract2 = ctx.contractAddress().toLowerCase();

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A allows contract1
    await ctx.rbac.setGroupPermissions(org.id, groupA.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contract1],
    });

    // Group B allows contract2
    await ctx.rbac.setGroupPermissions(org.id, groupB.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contract2],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
      roleId: role.id,
    });
    await ctx.fixture.addMembership(user.id, groupB.id, role.id);

    // User should have access to both contracts
    for (const contract of [contract1, contract2]) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        target_address: contract,
      });
      expect(result.allowed).toBe(true);
    }
  });

  test('claims UNIONed across roles', async ({ request }) => {
    const org = await ctx.fixture.createOrg('claimunionorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    await ctx.rbac.setGroupPermissions(org.id, groupA.id, {
      allow_methods: ['eth_sendTransaction'],
    });
    await ctx.rbac.setGroupPermissions(org.id, groupB.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    // Role A has reader
    const roleA = await ctx.fixture.createRole(org.id, 'roleA', ['reader']);
    // Role B has writer
    const roleB = await ctx.fixture.createRole(org.id, 'roleB', ['writer']);

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
      roleId: roleA.id,
    });
    await ctx.fixture.addMembership(user.id, groupB.id, roleB.id);

    // User should have UNION of claims: reader + writer
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['reader', 'writer'],
    });
    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('reader');
    expect(result.claims).toContain('writer');
  });

  test('rate limits take MAX across memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitmaxorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A: 50 RPS
    await ctx.rbac.setGroupPermissions(org.id, groupA.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 50,
      rate_limit_daily: 5000,
    });

    // Group B: 100 RPS
    await ctx.rbac.setGroupPermissions(org.id, groupB.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
      roleId: role.id,
    });
    await ctx.fixture.addMembership(user.id, groupB.id, role.id);

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
    await ctx.rbac.setGroupPermissions(org.id, root.id, {
      allow_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
    });

    // Child: A, B (intersection with root)
    await ctx.rbac.setGroupPermissions(org.id, child.id, {
      allow_methods: ['eth_call', 'eth_getBalance'],
    });

    // Sibling: D, E (completely different)
    await ctx.rbac.setGroupPermissions(org.id, sibling.id, {
      allow_methods: ['eth_chainId', 'eth_gasPrice'],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    // User in both child and sibling
    const { user, did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      roleId: role.id,
    });
    await ctx.fixture.addMembership(user.id, sibling.id, role.id);

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

    await ctx.rbac.setGroupPermissions(org.id, group1.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 30,
    });
    await ctx.rbac.setGroupPermissions(org.id, group2.id, {
      allow_methods: ['eth_getBalance'],
      rate_limit_rps: 60,
    });
    await ctx.rbac.setGroupPermissions(org.id, group3.id, {
      allow_methods: ['eth_blockNumber'],
      rate_limit_rps: 90,
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
      roleId: role.id,
    });
    await ctx.fixture.addMembership(user.id, group2.id, role.id);
    await ctx.fixture.addMembership(user.id, group3.id, role.id);

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

  test('owned contracts combine across memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ownedcombineorg');
    const contract1 = ctx.contractAddress().toLowerCase();
    const contract2 = ctx.contractAddress().toLowerCase();

    const group1 = await ctx.fixture.createGroup(org.id, 'group1');
    const group2 = await ctx.fixture.createGroup(org.id, 'group2');

    await ctx.rbac.setGroupPermissions(org.id, group1.id, {
      allow_methods: ['eth_call'],
      owned_addresses: [contract1],
    });
    await ctx.rbac.setGroupPermissions(org.id, group2.id, {
      allow_methods: ['eth_call'],
      owned_addresses: [contract2],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
      roleId: role.id,
    });
    await ctx.fixture.addMembership(user.id, group2.id, role.id);

    // User should own both contracts
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    expect(perms.owned_addresses).toContain(contract1);
    expect(perms.owned_addresses).toContain(contract2);
  });
});
