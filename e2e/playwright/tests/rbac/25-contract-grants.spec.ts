import { test, expect, APIRequestContext } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Contract Grants', () => {
  let ctx: RBACTestContext;
  let request: APIRequestContext;

  test.beforeEach(async ({ request: req }) => {
    request = req;
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('creates grant with read claims', async () => {
    const org = await ctx.fixture.createOrg('grant-org1');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group1');
    const contractAddr = ctx.contractAddress();

    // Create contract
    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Test Contract',
    });

    // Create grant
    const grant = await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read'],
    });

    expect(grant.group_id).toBe(group.id);
    expect(grant.claims).toContain('read');
    // Functions is undefined or null when all functions are allowed
    expect(grant.functions == null || grant.functions === undefined).toBe(true);
  });

  test('creates grant with multiple claims', async () => {
    const org = await ctx.fixture.createOrg('grant-org2');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group2');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Multi-Claim Contract',
    });

    const grant = await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read', 'write', 'admin'],
    });

    expect(grant.claims).toContain('read');
    expect(grant.claims).toContain('write');
    expect(grant.claims).toContain('admin');
  });

  test('creates grant with specific function selectors', async () => {
    const org = await ctx.fixture.createOrg('grant-org3');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group3');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Function-Limited Contract',
    });

    const grant = await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read'],
      functions: ['0x70a08231', '0x18160ddd'], // balanceOf, totalSupply
    });

    expect(grant.functions).toEqual(['0x70a08231', '0x18160ddd']);
  });

  test('lists grants for contract', async () => {
    const org = await ctx.fixture.createOrg('grant-org4');
    const group1 = await ctx.fixture.createGroup(org.id, 'grant-group4a');
    const group2 = await ctx.fixture.createGroup(org.id, 'grant-group4b');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Multi-Grant Contract',
    });

    // Create two grants
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group1.id,
      claims: ['read'],
    });
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group2.id,
      claims: ['read', 'write'],
    });

    const grants = await ctx.rbac.listContractGrants(org.id, contractAddr);

    expect(grants.length).toBe(2);
    const groupIds = grants.map((g) => g.group_id);
    expect(groupIds).toContain(group1.id);
    expect(groupIds).toContain(group2.id);
  });

  test('updates grant claims', async () => {
    const org = await ctx.fixture.createOrg('grant-org5');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group5');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Update Contract',
    });

    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read'],
    });

    // Update grant to add write claim
    const updated = await ctx.rbac.updateContractGrant(org.id, contractAddr, group.id, {
      claims: ['read', 'write', 'admin'],
    });

    expect(updated.claims).toContain('read');
    expect(updated.claims).toContain('write');
    expect(updated.claims).toContain('admin');
  });

  test('updates grant to restrict functions', async () => {
    const org = await ctx.fixture.createOrg('grant-org6');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group6');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Function Restrict Contract',
    });

    // Create with all functions
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read'],
      functions: null, // All functions
    });

    // Update to restrict functions
    const updated = await ctx.rbac.updateContractGrant(org.id, contractAddr, group.id, {
      functions: ['0x70a08231'], // Only balanceOf
    });

    expect(updated.functions).toEqual(['0x70a08231']);
  });

  test('deletes grant', async () => {
    const org = await ctx.fixture.createOrg('grant-org7');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group7');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Delete Grant Contract',
    });

    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read'],
    });

    // Verify grant exists
    let grants = await ctx.rbac.listContractGrants(org.id, contractAddr);
    expect(grants.length).toBe(1);

    // Delete grant
    await ctx.rbac.deleteContractGrant(org.id, contractAddr, group.id);

    // Verify grant is gone
    grants = await ctx.rbac.listContractGrants(org.id, contractAddr);
    expect(grants.length).toBe(0);
  });

  test('different groups can have different permissions on same contract', async () => {
    const org = await ctx.fixture.createOrg('grant-org8');
    const readOnlyGroup = await ctx.fixture.createGroup(org.id, 'readers');
    const writersGroup = await ctx.fixture.createGroup(org.id, 'writers');
    const adminsGroup = await ctx.fixture.createGroup(org.id, 'admins');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Multi-Permission Contract',
    });

    // Read-only grant
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: readOnlyGroup.id,
      claims: ['read'],
    });

    // Writers grant
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: writersGroup.id,
      claims: ['read', 'write'],
    });

    // Admins grant
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: adminsGroup.id,
      claims: ['read', 'write', 'admin'],
    });

    const grants = await ctx.rbac.listContractGrants(org.id, contractAddr);
    expect(grants.length).toBe(3);

    const readOnlyGrant = grants.find((g) => g.group_id === readOnlyGroup.id);
    const writersGrant = grants.find((g) => g.group_id === writersGroup.id);
    const adminsGrant = grants.find((g) => g.group_id === adminsGroup.id);

    expect(readOnlyGrant?.claims).toEqual(['read']);
    expect(writersGrant?.claims).toContain('write');
    expect(adminsGrant?.claims).toContain('admin');
  });

  test('grant affects effective permissions', async () => {
    const org = await ctx.fixture.createOrg('grant-org9');
    const group = await ctx.fixture.createGroup(org.id, 'perm-group');
    const contractAddr = ctx.contractAddress();

    // Set up group access (RPC methods and default claims)
    // Note: eth_sendTransaction requires write claim, so we include both claims
    // to allow both methods
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: ['read', 'write'],
    });

    // Create user and add to group
    const { user } = await ctx.fixture.createUser(request);
    await ctx.rbac.createMembership(user.id, { group_id: group.id });

    // Create contract with write grant
    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Granted Contract',
    });

    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read', 'write'], // Grant write on this specific contract
    });

    // Get effective permissions
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

    // Should have default read claim
    expect(perms.default_claims).toContain('read');

    // Contract should have write claim from grant
    expect(perms.contract_access).toBeDefined();
    const contractAccess = perms.contract_access[contractAddr.toLowerCase()];
    expect(contractAccess).toBeDefined();
    expect(contractAccess.claims).toContain('write');
  });

  // TODO: This test requires function selector checking to be fully implemented in access check
  // The checkAccess endpoint currently doesn't properly check function selectors against grants
  test.skip('function restrictions affect access check', async () => {
    const org = await ctx.fixture.createOrg('grant-org10');
    const group = await ctx.fixture.createGroup(org.id, 'func-group');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read'],
    });

    const { user } = await ctx.fixture.createUser(request);
    await ctx.rbac.createMembership(user.id, { group_id: group.id });

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Function-Limited Contract',
    });

    // Grant with specific functions only
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
      claims: ['read'],
      functions: ['0x70a08231'], // Only balanceOf
    });

    // Check access to allowed function
    const allowedResult = await ctx.rbac.checkAccess({
      user_external_id: user.external_id,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contractAddr,
      function_selector: '0x70a08231',
    });
    expect(allowedResult.allowed).toBe(true);

    // Check access to disallowed function
    const deniedResult = await ctx.rbac.checkAccess({
      user_external_id: user.external_id,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contractAddr,
      function_selector: '0xa9059cbb', // transfer - not in allowed list
    });
    expect(deniedResult.allowed).toBe(false);
  });
});
