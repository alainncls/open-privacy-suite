import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

test.describe('RBAC Contract Access Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('allows contract in allow_addresses', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractalloworg');
    const group = await ctx.fixture.createGroup(org.id, 'contractallowgroup');
    const role = await ctx.fixture.createReaderRole(org.id);
    const contractAddr = ctx.contractAddress().toLowerCase();

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contractAddr],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contractAddr,
    });

    expect(result.allowed).toBe(true);
  });

  test('denies contract NOT in allow_addresses', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractdenyorg');
    const group = await ctx.fixture.createGroup(org.id, 'contractdenygroup');
    const role = await ctx.fixture.createReaderRole(org.id);
    const allowedContract = ctx.contractAddress().toLowerCase();
    const deniedContract = ctx.contractAddress().toLowerCase();

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [allowedContract],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: deniedContract,
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('address');
  });

  test('owned contract bypasses allow_addresses list', async ({ request }) => {
    const org = await ctx.fixture.createOrg('ownedbypassorg');
    const group = await ctx.fixture.createGroup(org.id, 'ownedbypassgroup');
    const role = await ctx.fixture.createReaderRole(org.id);
    const ownedContract = ctx.contractAddress().toLowerCase();

    // Set permissions without the contract in allow_addresses
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [], // Empty allow list
      owned_addresses: [ownedContract], // But contract is owned
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: ownedContract,
    });

    expect(result.allowed).toBe(true);
  });

  test('allows any contract when allow_addresses is empty and no contract specified', async ({
    request,
  }) => {
    const org = await ctx.fixture.createOrg('anycontractorg');
    const group = await ctx.fixture.createGroup(org.id, 'anycontractgroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_blockNumber'],
      allow_addresses: [], // Empty - no contract restrictions
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Call without contract address
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
      // No contract_address specified
    });

    expect(result.allowed).toBe(true);
  });

  test('RPC eth_call to allowed contract succeeds', async ({ request }) => {
    // Use the default org since RPC handler always uses default org
    const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpccontractgroup');
    const role = await ctx.fixture.createRole(DEFAULT_ORG_ID, 'rpccontractrole', ['reader']);
    const contractAddr = ctx.contractAddress().toLowerCase();

    await ctx.rbac.setGroupPermissions(DEFAULT_ORG_ID, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contractAddr],
    });

    // Create user and add to the test group, removing default membership
    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      { to: contractAddr, data: '0x' },
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
  });

  test('RPC eth_call to disallowed contract fails', async ({ request }) => {
    // Use the default org since RPC handler always uses default org
    const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcdenycontractgroup');
    const role = await ctx.fixture.createRole(DEFAULT_ORG_ID, 'rpcdenyrole', ['reader']);
    const allowedContract = ctx.contractAddress().toLowerCase();
    const deniedContract = ctx.contractAddress().toLowerCase();

    await ctx.rbac.setGroupPermissions(DEFAULT_ORG_ID, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [allowedContract],
    });

    // Create user and add to the test group, removing default membership
    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      { to: deniedContract, data: '0x' },
      'latest',
    ]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
  });

  test('allows multiple contracts in allowlist', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multicontractorg');
    const group = await ctx.fixture.createGroup(org.id, 'multicontractgroup');
    const role = await ctx.fixture.createReaderRole(org.id);
    const contract1 = ctx.contractAddress().toLowerCase();
    const contract2 = ctx.contractAddress().toLowerCase();
    const contract3 = ctx.contractAddress().toLowerCase();

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contract1, contract2, contract3],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Test all contracts
    for (const contract of [contract1, contract2, contract3]) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        target_address: contract,
      });
      expect(result.allowed).toBe(true);
    }
  });

  test('contract address comparison is case-insensitive', async ({ request }) => {
    const org = await ctx.fixture.createOrg('caseorg');
    const group = await ctx.fixture.createGroup(org.id, 'casegroup');
    const role = await ctx.fixture.createReaderRole(org.id);
    const contractLower = '0xabcdef1234567890abcdef1234567890abcdef12';
    const contractUpper = '0xABCDEF1234567890ABCDEF1234567890ABCDEF12';

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [contractLower],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Request with uppercase address should still work
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contractUpper,
    });

    expect(result.allowed).toBe(true);
  });
});
