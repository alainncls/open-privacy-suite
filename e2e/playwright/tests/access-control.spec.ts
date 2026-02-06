import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../helpers/test-context.js';
import { makeRPCRequest, getJWTToken } from '../helpers/auth.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

test.describe('Access Control', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('allows method in whitelist', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'allowmethodgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_getBalance'],
      claims: ['read'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_getBalance', [
      '0x0000000000000000000000000000000000000000',
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
    expect(body).toHaveProperty('result');
  });

  test('denies method not in whitelist', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'denymethodgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_sendTransaction', [{}]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('not allowed');
  });

  test('denies banned user', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'bannedgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      banned: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('banned');
  });

  test('denies user without KYC', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'nokycgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('KYC');
  });

  test('denies user without membership', async ({ request }) => {
    // Create a user but don't add them to any group
    const userDID = ctx.did();
    const token = await getJWTToken(request, userDID);

    // Find the user, set KYC=true, and remove their default membership
    const user = await ctx.rbac.findUserByExternalId(userDID);
    if (user) {
      // Set KYC to true so we test membership denial, not KYC denial
      await ctx.rbac.updateUser(user.id, { kyc: true });

      const memberships = await ctx.rbac.listUserMemberships(user.id);
      for (const m of memberships) {
        await ctx.rbac.deleteMembership(user.id, m.membership.id);
      }
    }

    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    // Without membership, user has no permissions
    expect((body as { error: string }).error).toContain('no organization membership');
  });
});
