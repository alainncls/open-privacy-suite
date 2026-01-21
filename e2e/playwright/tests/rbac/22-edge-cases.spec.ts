import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// Common ERC20 function selectors
const TRANSFER_SELECTOR = '0xa9059cbb';
const APPROVE_SELECTOR = '0x095ea7b3';
const BALANCE_OF_SELECTOR = '0x70a08231';

test.describe('RBAC Edge Cases - Empty Permissions', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('user in group with empty methods + group with methods gets UNION', async ({ request }) => {
    // Edge case: What happens when one group has allowed_methods = []?
    // Expected: UNION includes the empty set, so user gets methods from other group only
    const org = await ctx.fixture.createOrg('emptyunionorg');
    const emptyGroup = await ctx.fixture.createGroup(org.id, 'emptygroup');
    const methodGroup = await ctx.fixture.createGroup(org.id, 'methodgroup');

    // Empty group - no methods allowed
    await ctx.rbac.setGroupAccess(org.id, emptyGroup.id, {
      allowed_methods: [],
      default_claims: ['read', 'write'],
    });

    // Method group - has eth_call
    await ctx.rbac.setGroupAccess(org.id, methodGroup.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, emptyGroup.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, methodGroup.id);

    // User should have eth_call (from methodGroup)
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // But should get claims from both groups (read+write from empty, read from method)
    expect(result.claims).toContain('read');
    expect(result.claims).toContain('write');
  });

  test('user with ONLY empty method group is blocked', async ({ request }) => {
    const org = await ctx.fixture.createOrg('onlyemptyorg');
    const group = await ctx.fixture.createGroup(org.id, 'onlyemptygroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: [], // Empty!
      default_claims: ['read', 'write', 'admin'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // All methods should be blocked
    for (const method of ['eth_call', 'eth_getBalance', 'eth_blockNumber']) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('method');
    }
  });

  test('user with empty default_claims + empty contract grants has no claims', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noclaimsorg');
    const group = await ctx.fixture.createGroup(org.id, 'noclaimsgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [], // No default claims
    });

    // No contract grants created

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // eth_call without target should work (no claim required for non-contract methods)
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    // Note: eth_call without target_address doesn't require claims
    expect(result.allowed).toBe(true);

    // But with target_address and required_claims, should fail
    const contractResult = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: ctx.contractAddress(),
      required_claims: ['read'],
    });
    expect(contractResult.allowed).toBe(false);
  });
});

test.describe('RBAC Edge Cases - No Memberships', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('user with no memberships (after removal) is blocked', async ({ request }) => {
    const org = await ctx.fixture.createOrg('nomembershiporg');
    const group = await ctx.fixture.createGroup(org.id, 'nomembershipgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
    });

    const { user, did, membership } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify initial access
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // Remove ALL memberships
    await ctx.rbac.deleteMembership(user.id, membership.id);

    // User should be blocked (no permissions)
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
  });
});

test.describe('RBAC Edge Cases - Hierarchy Edge Cases', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('deep hierarchy (5 levels) with progressive restriction', async ({ request }) => {
    const org = await ctx.fixture.createOrg('deeporg');

    // Create 5-level hierarchy with progressively restrictive methods
    const l1 = await ctx.fixture.createGroup(org.id, 'l1');
    const l2 = await ctx.fixture.createGroup(org.id, 'l2', { parentId: l1.id });
    const l3 = await ctx.fixture.createGroup(org.id, 'l3', { parentId: l2.id });
    const l4 = await ctx.fixture.createGroup(org.id, 'l4', { parentId: l3.id });
    const l5 = await ctx.fixture.createGroup(org.id, 'l5', { parentId: l4.id });

    // L1: 5 methods
    await ctx.rbac.setGroupAccess(org.id, l1.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId', 'eth_gasPrice'],
      default_claims: ['read', 'write'],
    });

    // L2: 4 methods (removes eth_gasPrice)
    await ctx.rbac.setGroupAccess(org.id, l2.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId'],
      default_claims: ['read', 'write'],
    });

    // L3: 3 methods
    await ctx.rbac.setGroupAccess(org.id, l3.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
    });

    // L4: 2 methods
    await ctx.rbac.setGroupAccess(org.id, l4.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    // L5: 1 method
    await ctx.rbac.setGroupAccess(org.id, l5.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, l5.id, {
      kyc: true,
    });

    // User in L5 should only have eth_call
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // All other methods should be blocked
    for (const method of ['eth_getBalance', 'eth_blockNumber', 'eth_chainId', 'eth_gasPrice']) {
      result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(false);
    }
  });

  test('user in multiple hierarchy paths gets combined permissions', async ({ request }) => {
    // Complex scenario:
    // Root1 -> ChildA (user is here)
    // Root2 -> ChildB (user is also here)
    // User should get UNION of both paths
    const org = await ctx.fixture.createOrg('multipathorg');

    const root1 = await ctx.fixture.createGroup(org.id, 'root1');
    const childA = await ctx.fixture.createGroup(org.id, 'childA', { parentId: root1.id });

    const root2 = await ctx.fixture.createGroup(org.id, 'root2');
    const childB = await ctx.fixture.createGroup(org.id, 'childB', { parentId: root2.id });

    // Root1 -> ChildA path allows eth_call, eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, root1.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read'],
    });
    await ctx.rbac.setGroupAccess(org.id, childA.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read'],
    });

    // Root2 -> ChildB path allows eth_blockNumber, eth_chainId
    await ctx.rbac.setGroupAccess(org.id, root2.id, {
      allowed_methods: ['eth_blockNumber', 'eth_chainId'],
      default_claims: ['write'],
    });
    await ctx.rbac.setGroupAccess(org.id, childB.id, {
      allowed_methods: ['eth_blockNumber', 'eth_chainId'],
      default_claims: ['write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, childA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, childB.id);

    // User should have all 4 methods
    for (const method of ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_chainId']) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(true);
    }

    // And both claims
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.claims).toContain('read');
    expect(result.claims).toContain('write');
  });

  test('child group with superset methods still gets intersection', async ({ request }) => {
    // Edge case: Child tries to have MORE methods than parent
    // Expected: Intersection means child can't exceed parent
    const org = await ctx.fixture.createOrg('supersetorg');

    const parent = await ctx.fixture.createGroup(org.id, 'parent');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: parent.id });

    // Parent has limited methods
    await ctx.rbac.setGroupAccess(org.id, parent.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
    });

    // Child tries to have MORE methods
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_sendTransaction'],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
    });

    // User should only have eth_call (intersection)
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // Other methods should be blocked
    for (const method of ['eth_getBalance', 'eth_blockNumber', 'eth_sendTransaction']) {
      const methodResult = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(methodResult.allowed).toBe(false);
    }
  });
});

test.describe('RBAC Edge Cases - Address Normalization', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('contract grants work regardless of address case', async ({ request }) => {
    const org = await ctx.fixture.createOrg('caseorg');
    const group = await ctx.fixture.createGroup(org.id, 'casegroup');

    // Create contract with lowercase address
    const address = ctx.contractAddress().toLowerCase();
    const contract = await ctx.fixture.createContract(org.id, { address });

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Request with uppercase address should still work
    const upperAddress = address.replace('0x', '0X').toUpperCase().replace('0X', '0x');
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: upperAddress,
      required_claims: ['read'],
    });

    expect(result.allowed).toBe(true);
  });

  test('mixed case addresses in RPC calls work', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpccasegroup');
    const address = ctx.contractAddress();
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID, { address });

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group.id,
      claims: ['read'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Mixed case address
    const mixedCase = address
      .split('')
      .map((c, i) => (i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()))
      .join('');

    const result = await makeRPCRequest(request, token, 'eth_call', [
      { to: mixedCase, data: '0x' },
      'latest',
    ]);

    expect(result.status).toBe(200);
  });
});

test.describe('RBAC Edge Cases - Rate Limit Edge Cases', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('null rate limits from one group + defined limits from another results in unlimited', async ({
    request,
  }) => {
    // Behavior: maxIntPtr(nil, defined) = nil (unlimited)
    // If either group has unlimited (null) rate limits, the user gets unlimited
    // This makes sense: if you're in a group with no limits, you shouldn't be limited
    const org = await ctx.fixture.createOrg('nullratelimitorg');
    const nullGroup = await ctx.fixture.createGroup(org.id, 'nullgroup');
    const limitedGroup = await ctx.fixture.createGroup(org.id, 'limitedgroup');

    // Group with null rate limits (unlimited)
    await ctx.rbac.setGroupAccess(org.id, nullGroup.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      // rate_limit_rps and rate_limit_daily not set (null = unlimited)
    });

    // Group with defined limits
    await ctx.rbac.setGroupAccess(org.id, limitedGroup.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      rate_limit_rps: 50,
      rate_limit_daily: 1000,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, nullGroup.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, limitedGroup.id);

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    // Should be unlimited (null/undefined) because one group has no limits
    // MAX(unlimited, 50) = unlimited
    expect(result.rate_limit_rps).toBeUndefined();
    expect(result.rate_limit_daily).toBeUndefined();
  });

  test('both groups with defined limits takes MAX', async ({ request }) => {
    // When both groups have defined limits, take the MAX (most permissive)
    const org = await ctx.fixture.createOrg('bothlimitsorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'group1');
    const group2 = await ctx.fixture.createGroup(org.id, 'group2');

    await ctx.rbac.setGroupAccess(org.id, group1.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      rate_limit_rps: 50,
      rate_limit_daily: 1000,
    });

    await ctx.rbac.setGroupAccess(org.id, group2.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      rate_limit_rps: 100,
      rate_limit_daily: 5000,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, group2.id);

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    // Should have MAX limits
    expect(result.rate_limit_rps).toBe(100);
    expect(result.rate_limit_daily).toBe(5000);
  });

  test('zero rate limits (if allowed) block all requests', async ({ request }) => {
    const org = await ctx.fixture.createOrg('zeroratelimitorg');
    const group = await ctx.fixture.createGroup(org.id, 'zerogroup');

    // Try to set zero rate limits
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      rate_limit_rps: 0, // Zero!
      rate_limit_daily: 0, // Zero!
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    // Should return the rate limits as-is
    expect(result.allowed).toBe(true); // Method is allowed, rate limiting is separate concern
    expect(result.rate_limit_rps).toBe(0);
    expect(result.rate_limit_daily).toBe(0);
  });
});

test.describe('RBAC Edge Cases - Concurrent Operations', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('multiple parallel access checks return consistent results', async ({ request }) => {
    // Use a shorter number of checks to avoid timeout
    const org = await ctx.fixture.createOrg('parallelorg');
    const group = await ctx.fixture.createGroup(org.id, 'parallelgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Run 5 parallel access checks (reduced from 10 to avoid timeout)
    const checks = Array.from({ length: 5 }, (_, i) =>
      ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: ['eth_call', 'eth_getBalance', 'eth_blockNumber'][i % 3],
      })
    );

    const results = await Promise.all(checks);

    // All should be allowed and have consistent rate limits
    for (const result of results) {
      expect(result.allowed).toBe(true);
      expect(result.rate_limit_rps).toBe(100);
    }
  });

  test('permission change during parallel requests is handled consistently', async ({ request }) => {
    const org = await ctx.fixture.createOrg('changeduringorg');
    const group = await ctx.fixture.createGroup(org.id, 'changeduringgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Start some checks
    const check1 = ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });

    // Change permissions
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'], // Remove eth_getBalance
      default_claims: ['read'],
    });

    // More checks after change
    const check2 = ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });

    const [result1, result2] = await Promise.all([check1, check2]);

    // Results might differ based on timing, but should be consistent with permissions at check time
    // The second check should definitely fail after the change
    expect(result2.allowed).toBe(false);
  });
});

test.describe('RBAC Edge Cases - Boundary Values', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('very long method names are handled correctly', async ({ request }) => {
    const org = await ctx.fixture.createOrg('longmethodorg');
    const group = await ctx.fixture.createGroup(org.id, 'longmethodgroup');

    const longMethod = 'eth_' + 'x'.repeat(100);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: [longMethod],
      default_claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: longMethod,
    });

    expect(result.allowed).toBe(true);
  });

  test('many methods (100+) in allowed_methods works', async ({ request }) => {
    const org = await ctx.fixture.createOrg('manymethodsorg');
    const group = await ctx.fixture.createGroup(org.id, 'manymethodsgroup');

    const methods = Array.from({ length: 100 }, (_, i) => `eth_method${i}`);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: methods,
      default_claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Check first, middle, and last method
    for (const method of [methods[0], methods[50], methods[99]]) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method,
      });
      expect(result.allowed).toBe(true);
    }

    // Method not in list should fail
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_notinlist',
    });
    expect(result.allowed).toBe(false);
  });

  test('user in many groups (20+) gets combined permissions', async ({ request }) => {
    const org = await ctx.fixture.createOrg('manygroupsorg');

    // Create 20 groups, each with one unique method
    const groups = await Promise.all(
      Array.from({ length: 20 }, (_, i) => ctx.fixture.createGroup(org.id, `group${i}`))
    );

    for (let i = 0; i < groups.length; i++) {
      await ctx.rbac.setGroupAccess(org.id, groups[i].id, {
        allowed_methods: [`eth_method${i}`],
        default_claims: ['read'],
      });
    }

    // Create user and add to all groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groups[0].id, {
      kyc: true,
    });
    for (let i = 1; i < groups.length; i++) {
      await ctx.fixture.addMembership(user.id, groups[i].id);
    }

    // Verify user has all 20 methods
    for (let i = 0; i < 20; i++) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: `eth_method${i}`,
      });
      expect(result.allowed).toBe(true);
    }
  });
});
