import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

test.describe('RBAC Permission Revocation - Membership Removal', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('removing membership revokes method access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('revokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'revokegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
    });

    const { user, did, membership } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify user has access
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // Remove membership
    await ctx.rbac.deleteMembership(user.id, membership.id);

    // Verify access is revoked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
  });

  test('removing one membership keeps access from other memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('partialmemberorg');
    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');

    // Group A: eth_call
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
    });

    // Group B: eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_getBalance'],
      default_claims: ['read'],
    });

    const { user, did, membership: membershipA } = await ctx.fixture.createUserWithMembership(
      request,
      groupA.id,
      { kyc: true }
    );
    const membershipB = await ctx.fixture.addMembership(user.id, groupB.id);

    // Verify user has both methods
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);

    // Remove membership A
    await ctx.rbac.deleteMembership(user.id, membershipA.id);

    // eth_call should now be denied (was from group A)
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);

    // eth_getBalance should still work (from group B)
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);
  });

  test('removing membership revokes contract-specific claims', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'contractrevokegroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'admin'],
    });

    const { user, did, membership } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify user has admin on contract
    let perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    expect(perms.contract_access[contract.address.toLowerCase()]?.claims).toContain('admin');

    // Remove membership
    await ctx.rbac.deleteMembership(user.id, membership.id);

    // Verify contract access is revoked
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(false);
  });

  test('RPC: removing membership immediately blocks RPC access', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcrevokegroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_blockNumber'],
      default_claims: ['read'],
    });

    const { user, token, membership } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Verify RPC works
    let result = await makeRPCRequest(request, token, 'eth_blockNumber');
    expect(result.status).toBe(200);

    // Remove membership
    await ctx.rbac.deleteMembership(user.id, membership.id);

    // RPC should now fail (method not allowed)
    result = await makeRPCRequest(request, token, 'eth_blockNumber');
    expect(result.status).toBe(403);
  });
});

test.describe('RBAC Permission Revocation - Grant Removal', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('removing contract grant revokes access to that contract', async ({ request }) => {
    const org = await ctx.fixture.createOrg('grantrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'grantrevokegroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [], // No default claims
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify access to contract
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(true);

    // Remove the grant
    await ctx.rbac.deleteContractGrant(org.id, contract.address, group.id);

    // Access should now be denied (no grant, no default_claims)
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(false);
  });

  test('removing grant from one group keeps access from another group', async ({ request }) => {
    const org = await ctx.fixture.createOrg('partialgrantorg');
    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupA.id,
      claims: ['read'],
    });

    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
      claims: ['write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // Verify user has both claims
    let perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    let access = perms.contract_access[contract.address.toLowerCase()];
    expect(access.claims).toContain('read');
    expect(access.claims).toContain('write');

    // Remove grant from group A
    await ctx.rbac.deleteContractGrant(org.id, contract.address, groupA.id);

    // User should still have write (from B), but not read (was from A)
    perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    access = perms.contract_access[contract.address.toLowerCase()];
    expect(access.claims).not.toContain('read');
    expect(access.claims).toContain('write');
  });

  test('updating grant to remove claims works correctly', async ({ request }) => {
    const org = await ctx.fixture.createOrg('updateclaimsorg');
    const group = await ctx.fixture.createGroup(org.id, 'updateclaimsgroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'admin'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify all claims
    let perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    expect(perms.contract_access[contract.address.toLowerCase()].claims).toContain('admin');

    // Update grant to remove admin
    await ctx.rbac.updateContractGrant(org.id, contract.address, group.id, {
      claims: ['read', 'write'], // No admin
    });

    // Admin should now be denied
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['admin'],
    });
    expect(result.allowed).toBe(false);
  });

  test('RPC: removing grant immediately blocks RPC access to contract', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcgrantrevokegroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [], // No default claims
    });

    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group.id,
      claims: ['read'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Verify RPC to contract works
    let result = await makeRPCRequest(request, token, 'eth_call', [
      { to: contract.address, data: '0x' },
      'latest',
    ]);
    expect(result.status).toBe(200);

    // Remove the grant
    await ctx.rbac.deleteContractGrant(DEFAULT_ORG_ID, contract.address, group.id);

    // RPC to contract should now fail
    result = await makeRPCRequest(request, token, 'eth_call', [
      { to: contract.address, data: '0x' },
      'latest',
    ]);
    expect(result.status).toBe(403);
  });
});

test.describe('RBAC Permission Revocation - Group Access Changes', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('removing method from group access blocks that method', async ({ request }) => {
    const org = await ctx.fixture.createOrg('methodrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'methodrevokegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify eth_getBalance works
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(true);

    // Update group access to remove eth_getBalance
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_blockNumber'], // Removed eth_getBalance
      default_claims: ['read'],
    });

    // eth_getBalance should now be blocked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_getBalance',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('method');
  });

  test('removing default_claims blocks access to unregistered contracts', async ({ request }) => {
    const org = await ctx.fixture.createOrg('defaultclaimrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'defaultclaimrevokegroup');
    const unknownContract = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Access to unknown contract should work via default_claims
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: unknownContract,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(true);

    // Remove default_claims
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [], // No default claims
    });

    // Access should now be blocked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: unknownContract,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(false);
  });

  test('reducing rate limits takes effect immediately', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ratelimitrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'ratelimitrevokegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify initial rate limits
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.rate_limit_rps).toBe(100);
    expect(result.rate_limit_daily).toBe(10000);

    // Reduce rate limits
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
      rate_limit_rps: 10,
      rate_limit_daily: 100,
    });

    // New rate limits should apply
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.rate_limit_rps).toBe(10);
    expect(result.rate_limit_daily).toBe(100);
  });
});

test.describe('RBAC Permission Revocation - User Status Changes', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('banning user immediately revokes all access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('banrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'banrevokegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: ['read', 'write', 'admin'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify full access
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['admin'],
    });
    expect(result.allowed).toBe(true);

    // Ban user
    await ctx.rbac.updateUser(user.id, { banned: true });

    // All access should be revoked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('banned');
  });

  test('revoking KYC immediately blocks access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('kycrevokeorg');
    const group = await ctx.fixture.createGroup(org.id, 'kycrevokegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
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

    // Revoke KYC
    await ctx.rbac.updateUser(user.id, { kyc: false });

    // Access should be blocked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('KYC');
  });

  test('RPC: banning user with valid token blocks all requests', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcbangroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_blockNumber', 'eth_chainId'],
      default_claims: ['read'],
    });

    const { user, token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Verify RPC works
    let result = await makeRPCRequest(request, token, 'eth_blockNumber');
    expect(result.status).toBe(200);

    // Ban user
    await ctx.rbac.updateUser(user.id, { banned: true });

    // All RPC requests should fail
    result = await makeRPCRequest(request, token, 'eth_blockNumber');
    expect(result.status).toBe(403);
    expect((result.body as { error: string }).error).toContain('banned');

    result = await makeRPCRequest(request, token, 'eth_chainId');
    expect(result.status).toBe(403);
    expect((result.body as { error: string }).error).toContain('banned');
  });
});

test.describe('RBAC Permission Revocation - Cascading Effects', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('deleting group revokes all access for members', async ({ request }) => {
    const org = await ctx.fixture.createOrg('deletegrouporg');
    const group = await ctx.fixture.createGroup(org.id, 'deletegroupgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify access
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(true);

    // Delete the group
    await ctx.rbac.deleteGroup(org.id, group.id);

    // Access should be revoked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
    });
    expect(result.allowed).toBe(false);
  });

  test('deleting contract removes all grants for that contract', async ({ request }) => {
    const org = await ctx.fixture.createOrg('deletecontractorg');
    const group = await ctx.fixture.createGroup(org.id, 'deletecontractgroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'admin'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify access
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['admin'],
    });
    expect(result.allowed).toBe(true);

    // Delete the contract
    await ctx.rbac.deleteContract(org.id, contract.address);

    // Access should be revoked
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(false);
  });
});
