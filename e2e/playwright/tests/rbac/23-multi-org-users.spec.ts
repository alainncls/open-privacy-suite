import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

/**
 * Multi-Organization User Tests
 *
 * These tests verify that users can be members of groups across multiple
 * organizations and that effective permissions are correctly isolated per org.
 */
test.describe('Multi-Organization Users', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test.describe('Cross-Org Membership', () => {
    test('user can be member of groups in multiple organizations', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('multiorg1');
      const org2 = await ctx.fixture.createOrg('multiorg2');

      // Create groups in each org
      const group1 = await ctx.fixture.createGroup(org1.id, 'group1');
      const group2 = await ctx.fixture.createGroup(org2.id, 'group2');

      // Create a user
      const { user } = await ctx.fixture.createUser(request);

      // Add user to groups in both orgs
      const membership1 = await ctx.rbac.createMembership(user.id, { group_id: group1.id });
      const membership2 = await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      expect(membership1.group_id).toBe(group1.id);
      expect(membership2.group_id).toBe(group2.id);

      // List memberships and verify both are present
      const memberships = await ctx.rbac.listUserMemberships(user.id);
      const groupIds = memberships.map((m) => m.membership.group_id);

      expect(groupIds).toContain(group1.id);
      expect(groupIds).toContain(group2.id);
    });

    test('memberships include group org_id for frontend grouping', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('orgidorg1');
      const org2 = await ctx.fixture.createOrg('orgidorg2');

      // Create groups
      const group1 = await ctx.fixture.createGroup(org1.id, 'orgidgroup1');
      const group2 = await ctx.fixture.createGroup(org2.id, 'orgidgroup2');

      // Create user with memberships in both orgs
      const { user } = await ctx.fixture.createUser(request);
      await ctx.rbac.createMembership(user.id, { group_id: group1.id });
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Get memberships with details
      const memberships = await ctx.rbac.listUserMemberships(user.id);

      // Verify each membership has group with org_id
      for (const m of memberships) {
        expect(m.group).toBeTruthy();
        expect(m.group.org_id).toBeTruthy();
      }

      // Verify memberships are in different orgs
      const orgIds = new Set(memberships.map((m) => m.group.org_id));
      expect(orgIds.has(org1.id)).toBe(true);
      expect(orgIds.has(org2.id)).toBe(true);
    });

    test('user can have similar groups in different orgs', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('samenameorg1');
      const org2 = await ctx.fixture.createOrg('samenameorg2');

      // Create groups in each org (slugs will be unique due to testId prefix)
      const group1 = await ctx.fixture.createGroup(org1.id, 'writers1');
      const group2 = await ctx.fixture.createGroup(org2.id, 'writers2');

      // Create user
      const { user } = await ctx.fixture.createUser(request);

      // Add to both groups
      await ctx.rbac.createMembership(user.id, { group_id: group1.id });
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Verify both memberships exist
      const memberships = await ctx.rbac.listUserMemberships(user.id);
      const testMemberships = memberships.filter(
        (m) => m.group.id === group1.id || m.group.id === group2.id
      );

      expect(testMemberships.length).toBe(2);

      // Verify they're in different orgs
      const orgIds = testMemberships.map((m) => m.group.org_id);
      expect(orgIds).toContain(org1.id);
      expect(orgIds).toContain(org2.id);
    });
  });

  test.describe('Per-Org Effective Permissions', () => {
    test('effective permissions are org-specific', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('effpermorg1');
      const org2 = await ctx.fixture.createOrg('effpermorg2');

      // Create groups with different access levels
      const group1 = await ctx.fixture.createGroup(org1.id, 'admins');
      const group2 = await ctx.fixture.createGroup(org2.id, 'readers');

      // Set different permissions for each group
      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_call', 'eth_sendTransaction'],
        default_claims: ['admin', 'write', 'read'],
        rate_limit_rps: 100,
      });

      await ctx.rbac.setGroupAccess(org2.id, group2.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
        rate_limit_rps: 10,
      });

      // Create user with memberships in both orgs
      const { user } = await ctx.fixture.createUser(request);
      await ctx.rbac.createMembership(user.id, { group_id: group1.id });
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Get effective permissions for org1
      const perms1 = await ctx.rbac.getEffectivePermissions(user.id, org1.slug);
      expect(perms1.org_id).toBe(org1.id);
      expect(perms1.default_claims).toContain('admin');
      expect(perms1.default_claims).toContain('write');
      expect(perms1.allowed_methods).toContain('eth_sendTransaction');
      expect(perms1.rate_limit_rps).toBe(100);

      // Get effective permissions for org2
      const perms2 = await ctx.rbac.getEffectivePermissions(user.id, org2.slug);
      expect(perms2.org_id).toBe(org2.id);
      expect(perms2.default_claims).toContain('read');
      expect(perms2.default_claims).not.toContain('admin');
      expect(perms2.allowed_methods).not.toContain('eth_sendTransaction');
      expect(perms2.rate_limit_rps).toBe(10);
    });

    test('permissions in one org do not affect another org', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('isolatedorg1');
      const org2 = await ctx.fixture.createOrg('isolatedorg2');

      // Create group only in org1
      const group1 = await ctx.fixture.createGroup(org1.id, 'privileged');
      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_sendRawTransaction'],
        default_claims: ['admin', 'write', 'read'],
      });

      // Create user with membership only in org1
      const { user } = await ctx.fixture.createUser(request);
      await ctx.rbac.createMembership(user.id, { group_id: group1.id });

      // Verify permissions in org1
      const perms1 = await ctx.rbac.getEffectivePermissions(user.id, org1.slug);
      expect(perms1.default_claims).toContain('admin');

      // Verify no permissions in org2 (user is not a member)
      // The endpoint should still return a result but with no/empty permissions
      const perms2 = await ctx.rbac.getEffectivePermissions(user.id, org2.slug);
      expect(perms2.default_claims?.length ?? 0).toBe(0);
      expect(perms2.allowed_methods?.length ?? 0).toBe(0);
    });

    test('multiple memberships in same org combine permissions', async ({ request }) => {
      // Create organization
      const org = await ctx.fixture.createOrg('combinedorg');

      // Create two groups with different permissions
      const readers = await ctx.fixture.createGroup(org.id, 'readers');
      const deployers = await ctx.fixture.createGroup(org.id, 'deployers');

      await ctx.rbac.setGroupAccess(org.id, readers.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      await ctx.rbac.setGroupAccess(org.id, deployers.id, {
        allowed_methods: ['eth_sendTransaction'],
        default_claims: ['deploy'],
      });

      // Create user with memberships in both groups
      const { user } = await ctx.fixture.createUser(request);
      await ctx.rbac.createMembership(user.id, { group_id: readers.id });
      await ctx.rbac.createMembership(user.id, { group_id: deployers.id });

      // Effective permissions should combine both groups
      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

      // Should have claims from both groups
      expect(perms.default_claims).toContain('read');
      expect(perms.default_claims).toContain('deploy');

      // Should have methods from both groups
      expect(perms.allowed_methods).toContain('eth_call');
      expect(perms.allowed_methods).toContain('eth_sendTransaction');
    });
  });

  test.describe('Cross-Org Access Checks', () => {
    test('access check respects org context', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('accessorg1');
      const org2 = await ctx.fixture.createOrg('accessorg2');

      // Create groups with different allowed methods
      const group1 = await ctx.fixture.createGroup(org1.id, 'txsenders');
      const group2 = await ctx.fixture.createGroup(org2.id, 'callers');

      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_sendTransaction'],
        default_claims: ['write'],
      });

      await ctx.rbac.setGroupAccess(org2.id, group2.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      // Create user with KYC and membership in group1
      const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
        kyc: true,
      });
      // Also add to group2
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Check access in org1 - should allow eth_sendTransaction
      const check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_sendTransaction',
      });
      expect(check1.allowed).toBe(true);

      // Check access in org1 - should deny eth_call (not in allowed methods)
      const check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
      });
      expect(check2.allowed).toBe(false);

      // Check access in org2 - should allow eth_call
      const check3 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
      });
      expect(check3.allowed).toBe(true);

      // Check access in org2 - should deny eth_sendTransaction
      const check4 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_sendTransaction',
      });
      expect(check4.allowed).toBe(false);
    });

    test('rate limits are org-specific', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('ratelimitorg1');
      const org2 = await ctx.fixture.createOrg('ratelimitorg2');

      // Create groups with different rate limits
      const group1 = await ctx.fixture.createGroup(org1.id, 'highrate');
      const group2 = await ctx.fixture.createGroup(org2.id, 'lowrate');

      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
        rate_limit_rps: 1000,
        rate_limit_daily: 100000,
      });

      await ctx.rbac.setGroupAccess(org2.id, group2.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
        rate_limit_rps: 10,
        rate_limit_daily: 1000,
      });

      // Create user with KYC and membership in group1
      const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
        kyc: true,
      });
      // Also add to group2
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Check access returns correct rate limits for each org
      const check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
      });
      expect(check1.allowed).toBe(true);
      expect(check1.rate_limit_rps).toBe(1000);
      expect(check1.rate_limit_daily).toBe(100000);

      const check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
      });
      expect(check2.allowed).toBe(true);
      expect(check2.rate_limit_rps).toBe(10);
      expect(check2.rate_limit_daily).toBe(1000);
    });
  });

  test.describe('Cross-Org Contract Access', () => {
    test('contract grants are org-specific', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('contractorg1');
      const org2 = await ctx.fixture.createOrg('contractorg2');

      // Create different contract addresses for each org (simpler test)
      const contractAddress1 = '0x' + '1'.repeat(40);
      const contractAddress2 = '0x' + '2'.repeat(40);

      await ctx.rbac.createContract(org1.id, {
        address: contractAddress1,
        name: 'Token in Org1',
      });

      await ctx.rbac.createContract(org2.id, {
        address: contractAddress2,
        name: 'Token in Org2',
      });

      // Create groups
      const group1 = await ctx.fixture.createGroup(org1.id, 'contractadmins');
      const group2 = await ctx.fixture.createGroup(org2.id, 'contractreaders');

      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      await ctx.rbac.setGroupAccess(org2.id, group2.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      // Grant different claims on the contracts
      await ctx.rbac.createContractGrant(org1.id, contractAddress1, {
        group_id: group1.id,
        claims: ['admin', 'write', 'read'],
      });

      await ctx.rbac.createContractGrant(org2.id, contractAddress2, {
        group_id: group2.id,
        claims: ['read'],
      });

      // Create user with KYC and membership in group1
      const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
        kyc: true,
      });
      // Also add to group2
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Check access with admin claim in org1 - should be allowed
      const check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
        target_address: contractAddress1,
        required_claims: ['admin'],
      });
      expect(check1.allowed).toBe(true);
      expect(check1.claims).toContain('admin');

      // Check access with admin claim in org2 - should be denied (only has read)
      const check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
        target_address: contractAddress2,
        required_claims: ['admin'],
      });
      expect(check2.allowed).toBe(false);

      // Check access with read claim in org2 - should be allowed
      const check3 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
        target_address: contractAddress2,
        required_claims: ['read'],
      });
      expect(check3.allowed).toBe(true);
    });
  });

  test.describe('Membership Management', () => {
    test('removing membership from one org does not affect other orgs', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('removeorg1');
      const org2 = await ctx.fixture.createOrg('removeorg2');

      // Create groups
      const group1 = await ctx.fixture.createGroup(org1.id, 'removegroup1');
      const group2 = await ctx.fixture.createGroup(org2.id, 'removegroup2');

      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      await ctx.rbac.setGroupAccess(org2.id, group2.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      // Create user with KYC and membership in group1
      const { user, did, membership } = await ctx.fixture.createUserWithMembership(
        request,
        group1.id,
        { kyc: true }
      );
      // Also add to group2
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Verify access in both orgs
      let check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
      });
      expect(check1.allowed).toBe(true);

      let check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
      });
      expect(check2.allowed).toBe(true);

      // Remove membership from org1 (the one created by createUserWithMembership)
      await ctx.rbac.deleteMembership(user.id, membership.id);

      // Verify access is now denied in org1
      check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
      });
      expect(check1.allowed).toBe(false);

      // Verify access is still allowed in org2
      check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
      });
      expect(check2.allowed).toBe(true);
    });

    test('user status (banned) affects all orgs', async ({ request }) => {
      // Create two organizations
      const org1 = await ctx.fixture.createOrg('bannedorg1');
      const org2 = await ctx.fixture.createOrg('bannedorg2');

      // Create groups
      const group1 = await ctx.fixture.createGroup(org1.id, 'bannedgroup1');
      const group2 = await ctx.fixture.createGroup(org2.id, 'bannedgroup2');

      await ctx.rbac.setGroupAccess(org1.id, group1.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      await ctx.rbac.setGroupAccess(org2.id, group2.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
      });

      // Create user with KYC and membership in group1
      const { user, did } = await ctx.fixture.createUserWithMembership(request, group1.id, {
        kyc: true,
      });
      // Also add to group2
      await ctx.rbac.createMembership(user.id, { group_id: group2.id });

      // Verify access in both orgs
      let check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
      });
      expect(check1.allowed).toBe(true);

      let check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
      });
      expect(check2.allowed).toBe(true);

      // Ban the user
      await ctx.rbac.updateUser(user.id, { banned: true });

      // Verify access is now denied in both orgs
      check1 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org1.slug,
        method: 'eth_call',
      });
      expect(check1.allowed).toBe(false);
      expect(check1.reason).toContain('banned');

      check2 = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org2.slug,
        method: 'eth_call',
      });
      expect(check2.allowed).toBe(false);
      expect(check2.reason).toContain('banned');
    });
  });
});
