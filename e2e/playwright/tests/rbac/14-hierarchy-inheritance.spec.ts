import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Hierarchy Inheritance', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('methods use INTERSECTION down hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('methodintersectorg');

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root allows A, B, C
    await ctx.rbac.setGroupPermissions(org.id, root.id, {
      allow_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
    });

    // Child allows A, B (intersection should be A, B)
    await ctx.rbac.setGroupPermissions(org.id, child.id, {
      allow_methods: ['eth_call', 'eth_getBalance'],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    // User in child group
    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      roleId: role.id,
    });

    // Should have intersection: eth_call, eth_getBalance
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

    // eth_blockNumber is NOT in child's allow_methods, so denied
    const resultBlock = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(resultBlock.allowed).toBe(false);
  });

  test('contracts use INTERSECTION down hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractintersectorg');
    const contract1 = ctx.contractAddress().toLowerCase();
    const contract2 = ctx.contractAddress().toLowerCase();
    const contract3 = ctx.contractAddress().toLowerCase();

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root allows C1, C2, C3
    await ctx.rbac.setGroupPermissions(org.id, root.id, {
      allow_methods: ['eth_call'],
      allow_contracts: [contract1, contract2, contract3],
    });

    // Child allows C1, C2 (intersection should be C1, C2)
    await ctx.rbac.setGroupPermissions(org.id, child.id, {
      allow_methods: ['eth_call'],
      allow_contracts: [contract1, contract2],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      roleId: role.id,
    });

    // C1 and C2 should be allowed
    for (const contract of [contract1, contract2]) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        contract_address: contract,
      });
      expect(result.allowed).toBe(true);
    }

    // C3 should be denied (not in child's list)
    const resultC3 = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      contract_address: contract3,
    });
    expect(resultC3.allowed).toBe(false);
  });

  test('owned contracts use UNION down hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ownedintersectorg');
    const contract1 = ctx.contractAddress().toLowerCase();
    const contract2 = ctx.contractAddress().toLowerCase();

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root owns C1
    await ctx.rbac.setGroupPermissions(org.id, root.id, {
      allow_methods: ['eth_call'],
      owned_contracts: [contract1],
    });

    // Child owns C2
    await ctx.rbac.setGroupPermissions(org.id, child.id, {
      allow_methods: ['eth_call'],
      owned_contracts: [contract2],
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { did, user } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      roleId: role.id,
    });

    // User should own both C1 (from root) and C2 (from child) via UNION
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    expect(perms.owned_contracts).toContain(contract1);
    expect(perms.owned_contracts).toContain(contract2);
  });

  test('rate limits use MINIMUM down hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitintersectorg');

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root: 100 RPS
    await ctx.rbac.setGroupPermissions(org.id, root.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    // Child: 50 RPS (more restrictive)
    await ctx.rbac.setGroupPermissions(org.id, child.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 50,
      rate_limit_daily: 5000,
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(true);
    // Should get the more restrictive (minimum) limits
    expect(result.rate_limit_rps).toBe(50);
    expect(result.rate_limit_daily).toBe(5000);
  });

  test('3-level hierarchy with progressive restriction', async ({ request }) => {
    const org = await ctx.fixture.createOrg('threelevelorg');

    // Create 3-level hierarchy
    const l1 = await ctx.fixture.createGroup(org.id, 'l1');
    const l2 = await ctx.fixture.createGroup(org.id, 'l2', { parentId: l1.id });
    const l3 = await ctx.fixture.createGroup(org.id, 'l3', { parentId: l2.id });

    // L1: allows A, B, C, D
    await ctx.rbac.setGroupPermissions(org.id, l1.id, {
      allow_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId'],
      rate_limit_rps: 100,
    });

    // L2: allows A, B, C (removes D)
    await ctx.rbac.setGroupPermissions(org.id, l2.id, {
      allow_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      rate_limit_rps: 75,
    });

    // L3: allows A, B (removes C)
    await ctx.rbac.setGroupPermissions(org.id, l3.id, {
      allow_methods: ['eth_call', 'eth_getBalance'],
      rate_limit_rps: 50,
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    const { did } = await ctx.fixture.createUserWithMembership(request, l3.id, {
      kyc: true,
      roleId: role.id,
    });

    // User in L3 should only have eth_call, eth_getBalance
    const resultCall = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(resultCall.allowed).toBe(true);
    expect(resultCall.rate_limit_rps).toBe(50);

    const resultBalance = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(resultBalance.allowed).toBe(true);

    // eth_blockNumber removed at L3
    const resultBlock = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(resultBlock.allowed).toBe(false);

    // eth_chainId removed at L2
    const resultChain = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_chainId',
    });
    expect(resultChain.allowed).toBe(false);
  });

  test('user in root group gets root permissions', async ({ request }) => {
    const org = await ctx.fixture.createOrg('rootpermorg');

    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root has more methods
    await ctx.rbac.setGroupPermissions(org.id, root.id, {
      allow_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      rate_limit_rps: 100,
    });

    // Child has fewer
    await ctx.rbac.setGroupPermissions(org.id, child.id, {
      allow_methods: ['eth_call'],
      rate_limit_rps: 50,
    });

    const role = await ctx.fixture.createReaderRole(org.id);

    // User in ROOT group (not child)
    const { did } = await ctx.fixture.createUserWithMembership(request, root.id, {
      kyc: true,
      roleId: role.id,
    });

    // User in root should have all root permissions
    const resultBlock = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });
    expect(resultBlock.allowed).toBe(true);
    expect(resultBlock.rate_limit_rps).toBe(100);
  });
});
