import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Claim Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('allows when user has required claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('claimorg');
    const group = await ctx.fixture.createGroup(org.id, 'claimgroup');
    const role = await ctx.fixture.createWriterRole(org.id); // Has reader + writer claims

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['writer'],
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('writer');
  });

  test('denies when user lacks required claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('lackclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'lackclaimgroup');
    const role = await ctx.fixture.createReaderRole(org.id); // Only has reader claim

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['deployer'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('denies when user has some but not all required claims', async ({ request }) => {
    const org = await ctx.fixture.createOrg('partialclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'partialclaimgroup');
    const role = await ctx.fixture.createWriterRole(org.id); // Has reader + writer, not deployer

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['writer', 'deployer'], // User has writer but not deployer
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('allows when no claims are required', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'noclaimgroup');
    const role = await ctx.fixture.createRole(org.id, 'noclaims', []); // No claims

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_blockNumber'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
      required_claims: [], // No claims required
    });

    expect(result.allowed).toBe(true);
  });

  test('admin role has all claims', async ({ request }) => {
    const org = await ctx.fixture.createOrg('adminclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'adminclaimgroup');
    const role = await ctx.fixture.createAdminRole(org.id);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Test all possible claims
    for (const claim of ['reader', 'writer', 'deployer', 'admin', 'upgrade'] as const) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_sendTransaction',
        required_claims: [claim],
      });
      expect(result.allowed).toBe(true);
      expect(result.claims).toContain(claim);
    }
  });

  test('returns all user claims in successful check', async ({ request }) => {
    const org = await ctx.fixture.createOrg('returnclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'returnclaimgroup');
    const role = await ctx.fixture.createRole(org.id, 'mixedclaims', [
      'reader',
      'writer',
      'deployer',
    ]);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('reader');
    expect(result.claims).toContain('writer');
    expect(result.claims).toContain('deployer');
  });

  test('user without role has no claims', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noroleclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'noroleclaimgroup');

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
    });

    // Create membership without a role
    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      // No roleId
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      required_claims: ['reader'],
    });

    // Should fail due to missing claim
    expect(result.allowed).toBe(false);
  });

  test('multiple claims all satisfied', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multiclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'multiclaimgroup');
    const role = await ctx.fixture.createAdminRole(org.id);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_sendTransaction'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['writer', 'deployer', 'admin'],
    });

    expect(result.allowed).toBe(true);
  });
});
