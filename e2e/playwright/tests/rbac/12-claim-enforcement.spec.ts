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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_sendTransaction'],
      claims: ['read', 'write'], // Has read + write claims
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['write'],
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('write');
  });

  test('denies when user lacks required claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('lackclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'lackclaimgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Only has read claim
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Request deploy claim which user doesn't have
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      required_claims: ['deploy'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('denies when user has some but not all required claims', async ({ request }) => {
    const org = await ctx.fixture.createOrg('partialclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'partialclaimgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_sendTransaction'],
      claims: ['read', 'write'], // Has read + write, not deploy
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['write', 'deploy'], // User has write but not deploy
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('allows when no claims are required', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'noclaimgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read'], // eth_blockNumber requires read claim
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
      required_claims: [], // No claims required
    });

    expect(result.allowed).toBe(true);
  });

  test('group with all claims grants all access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('adminclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'adminclaimgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_sendTransaction'],
      claims: ['read', 'write', 'deploy', 'admin', 'upgrade'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Test all possible claims
    for (const claim of ['read', 'write', 'deploy', 'admin', 'upgrade'] as const) {
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write', 'deploy'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('read');
    expect(result.claims).toContain('write');
    expect(result.claims).toContain('deploy');
  });

  test('group with empty claims denies claim-required access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noroleclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'noroleclaimgroup');

    // Grant read claim for eth_call method access, but no write claim
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Only read claim, no write
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      required_claims: ['write'], // Request write claim which user doesn't have
    });

    // Should fail due to missing write claim
    expect(result.allowed).toBe(false);
  });

  test('multiple claims all satisfied', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multiclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'multiclaimgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_sendTransaction'],
      claims: ['read', 'write', 'deploy', 'admin', 'upgrade'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['write', 'deploy', 'admin'],
    });

    expect(result.allowed).toBe(true);
  });
});
