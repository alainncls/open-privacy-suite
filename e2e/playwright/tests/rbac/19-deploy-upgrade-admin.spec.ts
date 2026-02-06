import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';
import { Claim } from '../../helpers/rbac-api.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// Common proxy/upgradeable contract function selectors
const UPGRADE_TO_SELECTOR = '0x3659cfe6'; // upgradeTo(address)
const UPGRADE_TO_AND_CALL_SELECTOR = '0x4f1ef286'; // upgradeToAndCall(address,bytes)
const CHANGE_ADMIN_SELECTOR = '0x8f283970'; // changeAdmin(address)
const OWNER_SELECTOR = '0x8da5cb5b'; // owner()
const TRANSFER_OWNERSHIP_SELECTOR = '0xf2fde38b'; // transferOwnership(address)

// Sample contract bytecode (minimal valid bytecode for testing)
const SAMPLE_BYTECODE = '0x6080604052600080fd'; // Simple contract that does nothing

test.describe('RBAC Deploy Claim Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('denies contract deployment without deploy claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('nodeployorg');
    const group = await ctx.fixture.createGroup(org.id, 'nodeploygroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // Has write but NOT deploy
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Contract deployment = eth_sendTransaction with no 'to' address
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['deploy'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('allows contract deployment with deploy claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('candeployorg');
    const group = await ctx.fixture.createGroup(org.id, 'candeploygroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'deploy'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['deploy'],
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('deploy');
  });

  test('deploy claim via group access allows deployment on granted contracts', async ({ request }) => {
    // Claims come from GroupAccess, not from ContractGrant
    // ContractGrant just links a group to a contract
    const org = await ctx.fixture.createOrg('grantdeployorg');
    const group = await ctx.fixture.createGroup(org.id, 'grantdeploygroup');
    const contract = await ctx.fixture.createContract(org.id);

    // Set deploy claim on the group via GroupAccess
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'deploy'], // Deploy claim is on GroupAccess
    });

    // Grant links the group to the contract (claims are inherited from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];
    // Claims on contract access come from the group's GroupAccess
    expect(contractAccess.claims).toContain('deploy');
    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');
  });

  test('RPC: deploy transaction blocked without deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcnodeploygroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Deployment transaction: eth_sendTransaction with data but no 'to'
    const deployTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', // Anvil default account
      data: SAMPLE_BYTECODE,
      gas: '0x100000',
      gasPrice: '0x3b9aca00',
      // No 'to' field = contract deployment
    };

    // RPC request should be blocked (403) because user lacks deploy claim
    const rpcResult = await makeRPCRequest(request, token, 'eth_sendTransaction', [deployTx]);
    expect(rpcResult.status).toBe(403);
    expect(rpcResult.body).toHaveProperty('error');
    const errorMsg = typeof rpcResult.body === 'object' && rpcResult.body !== null
      ? (rpcResult.body as { error?: string }).error || ''
      : '';
    expect(errorMsg.toLowerCase()).toContain('deploy');
  });

  test('RPC: deploy transaction allowed with deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpccandeploygroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'deploy'], // Has deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Deployment transaction: eth_sendTransaction with data but no 'to'
    const deployTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', // Anvil default account
      data: SAMPLE_BYTECODE,
      // No 'to' field = contract deployment
    };

    // RPC request should succeed (200) because user has deploy claim
    const rpcResult = await makeRPCRequest(request, token, 'eth_sendTransaction', [deployTx]);
    // Should be 200 (success) or at least not 403 (access denied)
    expect(rpcResult.status).not.toBe(403);
  });

  test('RPC: deploy with to=null blocked without deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpctonullgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Some clients send to: null for deployments
    const deployTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      to: null, // Explicit null = deployment
      data: SAMPLE_BYTECODE,
    };

    const rpcResult = await makeRPCRequest(request, token, 'eth_sendTransaction', [deployTx]);
    expect(rpcResult.status).toBe(403);
  });

  test('RPC: deploy with to="" blocked without deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcemptytogroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Some clients send to: "" for deployments
    const deployTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      to: '', // Empty string = deployment
      data: SAMPLE_BYTECODE,
    };

    const rpcResult = await makeRPCRequest(request, token, 'eth_sendTransaction', [deployTx]);
    expect(rpcResult.status).toBe(403);
  });

  test('RPC: regular transaction to contract allowed with write claim', async ({ request }) => {
    // This test ensures we didn't break normal transactions
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcwritegroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // Has write but NOT deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Regular transaction to an address (not deployment)
    const regularTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      to: '0x0000000000000000000000000000000000000001', // Has 'to' = not deployment
      value: '0x0',
      data: '0x',
    };

    // Should be allowed because user has write claim
    const rpcResult = await makeRPCRequest(request, token, 'eth_sendTransaction', [regularTx]);
    // Should not be 403 (access denied)
    expect(rpcResult.status).not.toBe(403);
  });

  test('RPC: eth_estimateGas for deployment blocked without deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcestimatenodeploygroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_estimateGas'],
      claims: ['read', 'write'], // No deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Estimate gas for deployment (no 'to' field)
    const estimateTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      data: SAMPLE_BYTECODE,
      // No 'to' = deployment estimation
    };

    // Should be blocked because estimating deployment gas requires deploy claim
    const rpcResult = await makeRPCRequest(request, token, 'eth_estimateGas', [estimateTx]);
    expect(rpcResult.status).toBe(403);
  });

  test('RPC: eth_estimateGas for deployment allowed with deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcestimatedeploygroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_estimateGas'],
      claims: ['read', 'write', 'deploy'], // Has deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Estimate gas for deployment (no 'to' field)
    const estimateTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      data: SAMPLE_BYTECODE,
      // No 'to' = deployment estimation
    };

    // Should be allowed because user has deploy claim
    const rpcResult = await makeRPCRequest(request, token, 'eth_estimateGas', [estimateTx]);
    expect(rpcResult.status).not.toBe(403);
  });

  test('RPC: eth_estimateGas for regular call allowed with read claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcestimatereadgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_estimateGas'],
      claims: ['read'], // Only read - no write or deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Estimate gas for regular call (has 'to' address)
    const estimateTx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      to: '0x0000000000000000000000000000000000000001',
      data: '0xa9059cbb',
    };

    // Should be allowed because user has read claim and it's not a deployment
    const rpcResult = await makeRPCRequest(request, token, 'eth_estimateGas', [estimateTx]);
    expect(rpcResult.status).not.toBe(403);
  });

  test('two groups combine to grant deploy permission', async ({ request }) => {
    // Group A: has write
    // Group B: has read + deploy
    // User in both: should have read + write + deploy (union of claims)
    const org = await ctx.fixture.createOrg('combinedeployorg');
    const groupA = await ctx.fixture.createGroup(org.id, 'writegroup');
    const groupB = await ctx.fixture.createGroup(org.id, 'deploygroup');

    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_sendTransaction'],
      claims: ['write'],
    });

    // eth_call requires read claim, so group B needs read claim
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'deploy'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      required_claims: ['deploy'],
    });

    expect(result.allowed).toBe(true);
  });
});

test.describe('RBAC Upgrade Claim Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('denies upgrade operation without upgrade claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noupgradeorg');
    const group = await ctx.fixture.createGroup(org.id, 'noupgradegroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has read+write but NOT upgrade
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No upgrade claim
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Check for upgrade claim - should fail because GroupAccess doesn't have upgrade
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['upgrade'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('allows upgrade operation with upgrade claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('canupgradeorg');
    const group = await ctx.fixture.createGroup(org.id, 'canupgradegroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has upgrade claim
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'upgrade'], // Has upgrade claim
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['upgrade'],
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('upgrade');
  });

  test('upgrade claim from group applies to all granted contracts', async ({ request }) => {
    // Claims come from GroupAccess, not from ContractGrant
    // All contracts granted to a group get the same claims from that group
    // To have different claims per contract, you need different groups
    const org = await ctx.fixture.createOrg('upgradespecificorg');
    const groupWithUpgrade = await ctx.fixture.createGroup(org.id, 'upgradegroup');
    const groupWithoutUpgrade = await ctx.fixture.createGroup(org.id, 'noupgradegroup');
    const contractA = await ctx.fixture.createContract(org.id);
    const contractB = await ctx.fixture.createContract(org.id);

    // Group with upgrade claim
    await ctx.rbac.setGroupAccess(org.id, groupWithUpgrade.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'upgrade'],
    });

    // Group without upgrade claim
    await ctx.rbac.setGroupAccess(org.id, groupWithoutUpgrade.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });

    // Contract A gets grant from upgrade group
    await ctx.rbac.createContractGrant(org.id, contractA.address, {
      group_id: groupWithUpgrade.id,
    });
    // Contract B gets grant from non-upgrade group
    await ctx.rbac.createContractGrant(org.id, contractB.address, {
      group_id: groupWithoutUpgrade.id,
    });

    // User is member of both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupWithUpgrade.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupWithoutUpgrade.id);

    // Verify effective permissions show correct per-contract claims
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

    // Contract A should have upgrade (from groupWithUpgrade)
    const accessA = perms.contract_access[contractA.address.toLowerCase()];
    expect(accessA.claims).toContain('upgrade');
    expect(accessA.claims).toContain('read');
    expect(accessA.claims).toContain('write');

    // Contract B should NOT have upgrade (from groupWithoutUpgrade)
    const accessB = perms.contract_access[contractB.address.toLowerCase()];
    expect(accessB.claims).not.toContain('upgrade');
    expect(accessB.claims).toContain('read');
    expect(accessB.claims).toContain('write');
  });

  test('user with no upgrade claim on any contract fails upgrade check', async ({ request }) => {
    // Test that required_claims works when user genuinely lacks the claim
    const org = await ctx.fixture.createOrg('noupgradeatallorg');
    const group = await ctx.fixture.createGroup(org.id, 'noupgradeatallgroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has only read+write, no upgrade
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No upgrade claim
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Upgrade check should fail (GroupAccess doesn't have upgrade)
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['upgrade'],
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });

  test('upgrade claim combined across multiple groups', async ({ request }) => {
    // User is member of two groups - groupA has write, groupB has upgrade
    // Combined, user should have write + upgrade claims
    const org = await ctx.fixture.createOrg('combineupgradeorg');
    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract = await ctx.fixture.createContract(org.id);

    // Group A has write claim
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupA.id,
    });

    // Group B has upgrade claim (plus read for eth_call)
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'upgrade'],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // User gets upgrade from groupB
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['upgrade'],
    });

    expect(result.allowed).toBe(true);
  });
});

test.describe('RBAC Admin Claim Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('denies admin operation without admin claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('noadminorg');
    const group = await ctx.fixture.createGroup(org.id, 'noadmingroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has read+write but NOT admin
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No admin claim
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['admin'],
    });

    expect(result.allowed).toBe(false);
  });

  test('allows admin operation with admin claim', async ({ request }) => {
    const org = await ctx.fixture.createOrg('canadminorg');
    const group = await ctx.fixture.createGroup(org.id, 'canadmingroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has admin claim
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'admin'], // Has admin claim
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['admin'],
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('admin');
  });

  test('admin claim grants full access to contract', async ({ request }) => {
    const org = await ctx.fixture.createOrg('fulladminorg');
    const group = await ctx.fixture.createGroup(org.id, 'fulladmingroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has all claims including admin
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'deploy', 'upgrade', 'admin'], // All claims
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Should be able to perform any operation
    for (const claim of ['read', 'write', 'deploy', 'upgrade', 'admin'] as Claim[]) {
      const result = await ctx.rbac.checkAccess({
        user_external_id: did,
        org_slug: org.slug,
        method: 'eth_sendTransaction',
        target_address: contract.address,
        required_claims: [claim],
      });
      expect(result.allowed).toBe(true);
      expect(result.claims).toContain(claim);
    }
  });

  test('admin claim inherited through group hierarchy when child has no grant', async ({ request }) => {
    // Within a hierarchy, grants use INTERSECTION (child narrows parent).
    // If child has no grant for a contract, user inherits parent's grant.
    // Claims come from GroupAccess, not from grants.
    const org = await ctx.fixture.createOrg('adminhierarchyorg');
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });
    const contract = await ctx.fixture.createContract(org.id);

    // Root has admin claim in GroupAccess and grant on contract
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'admin'], // Admin claim is on GroupAccess
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: root.id,
    });

    // Child has NO grant on this contract - user should inherit from parent
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    // No grant created for child

    const { user, did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
    });

    // User in child should inherit admin from parent (since child has no grant)
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    expect(contractAccess).toBeDefined();
    expect(contractAccess.claims).toContain('admin');
    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');
  });

  test('hierarchy grants use INTERSECTION when both parent and child have grants', async ({ request }) => {
    // Within a hierarchy, if both parent and child have grants for the same contract,
    // claims are INTERSECTED (child narrows parent).
    // Claims come from GroupAccess, so we need different claims on parent vs child.
    const org = await ctx.fixture.createOrg('hierarchyintersectorg');
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });
    const contract = await ctx.fixture.createContract(org.id);

    // Root has read+write+admin in GroupAccess
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'admin'], // Admin claim on root
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: root.id,
    });

    // Child has only read+write (narrows parent by removing admin)
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No admin claim on child
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: child.id,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
    });

    // User in child should have INTERSECTION = read+write (no admin)
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    expect(contractAccess).toBeDefined();
    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');
    expect(contractAccess.claims).not.toContain('admin'); // INTERSECTED out
  });

  test('multiple claims required simultaneously', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multiclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'multiclaimgroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has all required claims
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write', 'admin'], // All required claims
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Require all three claims at once
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['read', 'write', 'admin'],
    });

    expect(result.allowed).toBe(true);
  });

  test('missing one claim from multiple required fails', async ({ request }) => {
    const org = await ctx.fixture.createOrg('missingclaimorg');
    const group = await ctx.fixture.createGroup(org.id, 'missingclaimgroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has read+write but NOT admin
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'], // No admin claim
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Require read+write+admin - should fail because admin is missing
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['read', 'write', 'admin'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('claim');
  });
});

test.describe('RBAC All Claims Combined', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('user with all claims can perform any operation', async ({ request }) => {
    const org = await ctx.fixture.createOrg('allclaimsorg');
    const group = await ctx.fixture.createGroup(org.id, 'allclaimsgroup');
    const contract = await ctx.fixture.createContract(org.id);

    // GroupAccess has all claims
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_getBalance', 'eth_blockNumber'],
      claims: ['read', 'write', 'deploy', 'upgrade', 'admin'], // All claims
    });

    // Grant links group to contract (claims come from GroupAccess)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

    // Should have all methods
    expect(perms.allowed_methods).toContain('eth_call');
    expect(perms.allowed_methods).toContain('eth_sendTransaction');
    expect(perms.allowed_methods).toContain('eth_getBalance');
    expect(perms.allowed_methods).toContain('eth_blockNumber');

    // Should have all default claims (from GroupAccess)
    expect(perms.claims).toContain('read');
    expect(perms.claims).toContain('write');
    expect(perms.claims).toContain('deploy');
    expect(perms.claims).toContain('upgrade');
    expect(perms.claims).toContain('admin');

    // Should have all claims on the contract (inherited from GroupAccess)
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];
    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');
    expect(contractAccess.claims).toContain('deploy');
    expect(contractAccess.claims).toContain('upgrade');
    expect(contractAccess.claims).toContain('admin');
  });

  test('claims assembled from 5 different groups', async ({ request }) => {
    // Each group contributes one claim, user in all groups gets UNION of claims
    const org = await ctx.fixture.createOrg('fivegroupsorg');
    const groups = await Promise.all([
      ctx.fixture.createGroup(org.id, 'readgroup'),
      ctx.fixture.createGroup(org.id, 'writegroup'),
      ctx.fixture.createGroup(org.id, 'deploygroup'),
      ctx.fixture.createGroup(org.id, 'upgradegroup'),
      ctx.fixture.createGroup(org.id, 'admingroup'),
    ]);

    const contract = await ctx.fixture.createContract(org.id);

    // Each group has different claims (claims are in GroupAccess)
    // Note: eth_call requires read, eth_sendTransaction requires write
    // Groups must have valid claim-method combinations
    const groupConfigs = [
      { methods: ['eth_call'], claims: ['read'] as Claim[] },                          // readgroup
      { methods: ['eth_call', 'eth_sendTransaction'], claims: ['read', 'write'] as Claim[] },  // writegroup
      { methods: ['eth_call', 'eth_sendTransaction'], claims: ['read', 'write', 'deploy'] as Claim[] },    // deploygroup
      { methods: ['eth_call', 'eth_sendTransaction'], claims: ['read', 'write', 'upgrade'] as Claim[] },   // upgradegroup
      { methods: ['eth_call', 'eth_sendTransaction'], claims: ['read', 'write', 'admin'] as Claim[] },     // admingroup
    ];

    for (let i = 0; i < groups.length; i++) {
      await ctx.rbac.setGroupAccess(org.id, groups[i].id, {
        allowed_methods: groupConfigs[i].methods,
        claims: groupConfigs[i].claims,
      });
      await ctx.rbac.createContractGrant(org.id, contract.address, {
        group_id: groups[i].id,
      });
    }

    // Create user and add to all 5 groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groups[0].id, {
      kyc: true,
    });
    for (let i = 1; i < groups.length; i++) {
      await ctx.fixture.addMembership(user.id, groups[i].id);
    }

    // User should have UNION of all claims from all groups
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    const allClaims: Claim[] = ['read', 'write', 'deploy', 'upgrade', 'admin'];
    for (const claim of allClaims) {
      expect(contractAccess.claims).toContain(claim);
    }
  });
});
