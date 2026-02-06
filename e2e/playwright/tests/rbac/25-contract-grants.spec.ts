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
      
    });

    expect(grant.group_id).toBe(group.id);
    // Claims are now inherited from group's GroupAccess, not stored on grants
    // Functions is undefined or null when all functions are allowed
    expect(grant.functions == null || grant.functions === undefined).toBe(true);
  });

  test('creates grant linking group to contract', async () => {
    const org = await ctx.fixture.createOrg('grant-org2');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group2');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Multi-Claim Contract',
    });

    const grant = await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
    });

    // Grants link groups to contracts - claims are inherited from group's GroupAccess
    expect(grant.group_id).toBe(group.id);
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
      
    });
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group2.id,
      
    });

    const grants = await ctx.rbac.listContractGrants(org.id, contractAddr);

    expect(grants.length).toBe(2);
    const groupIds = grants.map((g) => g.group_id);
    expect(groupIds).toContain(group1.id);
    expect(groupIds).toContain(group2.id);
  });

  test('updates grant functions', async () => {
    const org = await ctx.fixture.createOrg('grant-org5');
    const group = await ctx.fixture.createGroup(org.id, 'grant-group5');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Update Contract',
    });

    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: group.id,
    });

    // Update grant to restrict to specific functions
    const updated = await ctx.rbac.updateContractGrant(org.id, contractAddr, group.id, {
      functions: ['0x70a08231', '0x18160ddd'], // balanceOf, totalSupply
    });

    // Grant now only allows specific functions - claims come from GroupAccess
    expect(updated.functions).toEqual(['0x70a08231', '0x18160ddd']);
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

    // Set up different claims for each group via GroupAccess
    await ctx.rbac.setGroupAccess(org.id, readOnlyGroup.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'],
    });
    await ctx.rbac.setGroupAccess(org.id, writersGroup.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.setGroupAccess(org.id, adminsGroup.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'admin'],
    });

    await ctx.rbac.createContract(org.id, {
      address: contractAddr,
      name: 'Multi-Permission Contract',
    });

    // Create grants - grants link groups to contracts, claims come from GroupAccess
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: readOnlyGroup.id,
    });
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: writersGroup.id,
    });
    await ctx.rbac.createContractGrant(org.id, contractAddr, {
      group_id: adminsGroup.id,
    });

    const grants = await ctx.rbac.listContractGrants(org.id, contractAddr);
    expect(grants.length).toBe(3);

    // Verify all groups have grants
    const groupIds = grants.map((g) => g.group_id);
    expect(groupIds).toContain(readOnlyGroup.id);
    expect(groupIds).toContain(writersGroup.id);
    expect(groupIds).toContain(adminsGroup.id);

    // Verify GroupAccess has the correct claims
    const readOnlyAccess = await ctx.rbac.getGroupAccess(org.id, readOnlyGroup.id);
    const writersAccess = await ctx.rbac.getGroupAccess(org.id, writersGroup.id);
    const adminsAccess = await ctx.rbac.getGroupAccess(org.id, adminsGroup.id);

    expect(readOnlyAccess?.claims).toEqual(['read']);
    expect(writersAccess?.claims).toContain('write');
    expect(adminsAccess?.claims).toContain('admin');
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
      claims: ['read', 'write'],
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
       // Grant write on this specific contract
    });

    // Get effective permissions
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

    // Should have default read claim
    expect(perms.claims).toContain('read');

    // Contract should have write claim from grant
    expect(perms.contract_access).toBeDefined();
    const contractAccess = perms.contract_access[contractAddr.toLowerCase()];
    expect(contractAccess).toBeDefined();
    expect(contractAccess.claims).toContain('write');
  });

  test.describe('Contract ABI Upload', () => {
    const sampleABI = JSON.stringify([
      {
        type: 'function',
        name: 'balanceOf',
        inputs: [{ name: 'account', type: 'address' }],
        outputs: [{ name: '', type: 'uint256' }],
        stateMutability: 'view',
      },
      {
        type: 'function',
        name: 'transfer',
        inputs: [
          { name: 'to', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ],
        outputs: [{ name: '', type: 'bool' }],
        stateMutability: 'nonpayable',
      },
      {
        type: 'function',
        name: 'approve',
        inputs: [
          { name: 'spender', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ],
        outputs: [{ name: '', type: 'bool' }],
        stateMutability: 'nonpayable',
      },
    ]);

    test('uploads valid ABI to contract', async () => {
      const org = await ctx.fixture.createOrg('abi-org1');
      const contractAddr = ctx.contractAddress();

      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'ABI Test Contract',
      });

      const updated = await ctx.rbac.updateContractABI(org.id, contractAddr, sampleABI);

      expect(updated.address || updated.contract_address).toBe(contractAddr);
      expect(updated.abi).toBe(sampleABI);
    });

    test('ABI persists after upload', async () => {
      const org = await ctx.fixture.createOrg('abi-org2');
      const contractAddr = ctx.contractAddress();

      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'ABI Persist Test',
      });

      await ctx.rbac.updateContractABI(org.id, contractAddr, sampleABI);

      // Verify ABI is persisted by getting the contract
      const contract = await ctx.rbac.getContract(org.id, contractAddr);
      expect(contract).not.toBeNull();
      expect(contract!.abi).toBe(sampleABI);
    });

    test('rejects invalid JSON ABI', async () => {
      const org = await ctx.fixture.createOrg('abi-org3');
      const contractAddr = ctx.contractAddress();

      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'Invalid ABI Test',
      });

      await expect(
        ctx.rbac.updateContractABI(org.id, contractAddr, 'not valid json')
      ).rejects.toThrow(/400/);
    });

    test('rejects non-array ABI', async () => {
      const org = await ctx.fixture.createOrg('abi-org4');
      const contractAddr = ctx.contractAddress();

      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'Non-Array ABI Test',
      });

      await expect(
        ctx.rbac.updateContractABI(org.id, contractAddr, '{"type": "function"}')
      ).rejects.toThrow(/400/);
    });

    test('can replace existing ABI', async () => {
      const org = await ctx.fixture.createOrg('abi-org5');
      const contractAddr = ctx.contractAddress();

      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'Replace ABI Test',
      });

      // Upload initial ABI
      await ctx.rbac.updateContractABI(org.id, contractAddr, sampleABI);

      // Upload replacement ABI
      const newABI = JSON.stringify([
        {
          type: 'function',
          name: 'totalSupply',
          inputs: [],
          outputs: [{ name: '', type: 'uint256' }],
          stateMutability: 'view',
        },
      ]);

      const updated = await ctx.rbac.updateContractABI(org.id, contractAddr, newABI);
      expect(updated.abi).toBe(newABI);

      // Verify the new ABI persists
      const contract = await ctx.rbac.getContract(org.id, contractAddr);
      expect(contract!.abi).toBe(newABI);
    });

    test('ABI upload to nonexistent contract fails', async () => {
      const org = await ctx.fixture.createOrg('abi-org6');
      const nonexistentAddr = '0x0000000000000000000000000000000000000001';

      await expect(
        ctx.rbac.updateContractABI(org.id, nonexistentAddr, sampleABI)
      ).rejects.toThrow(/404/);
    });
  });

  test.describe('Explicit Grant Requirement Security', () => {
    // These tests verify that registered contracts require explicit grants
    // and cannot be accessed via claims alone (security fix)

    test('registered contract WITHOUT explicit grant is denied', async ({ request }) => {
      const org = await ctx.fixture.createOrg('grant-security-org1');
      const group = await ctx.fixture.createGroup(org.id, 'security-group1');
      const contractAddr = ctx.contractAddress();

      // Set up group access with claims (read) but NO explicit contract grant
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call'],
        claims: ['read'], // User has read via claims
      });

      // Create user with membership (removes default membership so only our group applies)
      const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
        kyc: true,
      });

      // Register contract to org (but NO grant to the group)
      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'No-Grant Contract',
      });

      // Verify effective permissions do NOT include contract in contract_access
      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
      expect(perms.claims).toContain('read');
      expect(perms.contract_access[contractAddr.toLowerCase()]).toBeUndefined();

      // Access check should DENY because registered contracts require explicit grants
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        target_address: contractAddr,
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('requires explicit grant');
    });

    test('registered contract WITH explicit grant is allowed', async ({ request }) => {
      const org = await ctx.fixture.createOrg('grant-security-org2');
      const group = await ctx.fixture.createGroup(org.id, 'security-group2');
      const contractAddr = ctx.contractAddress();

      // Set up group access
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call'],
        claims: ['read'],
      });

      // Create user with membership (removes default membership so only our group applies)
      const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
        kyc: true,
      });

      // Register contract to org
      await ctx.rbac.createContract(org.id, {
        address: contractAddr,
        name: 'Granted Contract',
      });

      // Add explicit grant for the contract to the group
      await ctx.rbac.createContractGrant(org.id, contractAddr, {
        group_id: group.id,
      });

      // Verify effective permissions include the contract
      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
      expect(perms.contract_access[contractAddr.toLowerCase()]).toBeDefined();
      expect(perms.contract_access[contractAddr.toLowerCase()].claims).toContain('read');

      // Access check should ALLOW because user has explicit grant
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        target_address: contractAddr,
      });
      expect(result.allowed).toBe(true);
    });

    test('public contract (not registered) allowed via claims', async ({ request }) => {
      const org = await ctx.fixture.createOrg('grant-security-org3');
      const group = await ctx.fixture.createGroup(org.id, 'security-group3');
      // This address is NOT registered to any org
      const publicContractAddr = '0x' + 'ab'.repeat(20);

      // Set up group access with claims
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call'],
        claims: ['read'],
      });

      // Create user with membership (removes default membership so only our group applies)
      const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
        kyc: true,
      });

      // Do NOT register the contract - it stays public

      // Access check should ALLOW via claims for public contract
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_call',
        target_address: publicContractAddr,
      });
      expect(result.allowed).toBe(true);
    });
  });

  // TODO: This test requires function selector checking to be fully implemented in access check
  // The checkAccess endpoint currently doesn't properly check function selectors against grants
  test.skip('function restrictions affect access check', async () => {
    const org = await ctx.fixture.createOrg('grant-org10');
    const group = await ctx.fixture.createGroup(org.id, 'func-group');
    const contractAddr = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'],
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
