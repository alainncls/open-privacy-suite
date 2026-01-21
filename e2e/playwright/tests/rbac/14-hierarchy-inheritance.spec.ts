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
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
    });

    // Child allows A, B (intersection should be A, B)
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // User in child group
    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
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

  test('contract grants use UNION across hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractunionorg');

    // Create contracts
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);
    const contract3 = await ctx.fixture.createContract(org.id);

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root has grant for C1 only
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: root.id,
      claims: ['read', 'write'],
    });

    // Child has grant for C2 only
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: child.id,
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
    });

    // User in child should have access to all contracts via default_claims
    // Plus specific grants for C1 (from parent) and C2 (from child)
    for (const contract of [contract1, contract2, contract3]) {
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

  test('admin grants use UNION down hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('adminintersectorg');

    // Create contracts
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root has admin on C1
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: root.id,
      claims: ['admin'],
    });

    // Child has admin on C2
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: child.id,
      claims: ['admin'],
    });

    const { did, user } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
    });

    // User should have admin on both C1 (from root) and C2 (from child) via UNION
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    expect(perms.contract_access[contract1.address]?.claims).toContain('admin');
    expect(perms.contract_access[contract2.address]?.claims).toContain('admin');
  });

  test('rate limits use MINIMUM down hierarchy', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitintersectorg');

    // Create hierarchy: root -> child
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });

    // Root: 100 RPS
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    // Child: 50 RPS (more restrictive)
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 50,
      rate_limit_daily: 5000,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
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
    await ctx.rbac.setGroupAccess(org.id, l1.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
    });

    // L2: allows A, B, C (removes D)
    await ctx.rbac.setGroupAccess(org.id, l2.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 75,
    });

    // L3: allows A, B (removes C)
    await ctx.rbac.setGroupAccess(org.id, l3.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 50,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, l3.id, {
      kyc: true,
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
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
    });

    // Child has fewer
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 50,
    });

    // User in ROOT group (not child)
    const { did } = await ctx.fixture.createUserWithMembership(request, root.id, {
      kyc: true,
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
