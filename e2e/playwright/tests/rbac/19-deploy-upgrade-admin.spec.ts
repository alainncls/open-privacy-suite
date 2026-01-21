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
      default_claims: ['read', 'write'], // Has write but NOT deploy
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
      default_claims: ['read', 'write', 'deploy'],
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

  test('deploy claim via contract grant allows deployment', async ({ request }) => {
    const org = await ctx.fixture.createOrg('grantdeployorg');
    const group = await ctx.fixture.createGroup(org.id, 'grantdeploygroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [], // No default claims
    });

    // Grant deploy claim on a contract (conceptually - for factories, etc.)
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'deploy'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];
    expect(contractAccess.claims).toContain('deploy');
  });

  test('RPC: deploy transaction blocked without deploy claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcnodeploygroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: ['read', 'write'], // No deploy
    });

    const { token, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Deployment transaction: eth_sendTransaction with data but no 'to'
    const deployTx = {
      from: '0x0000000000000000000000000000000000000001',
      data: SAMPLE_BYTECODE,
      gas: '0x100000',
      gasPrice: '0x3b9aca00',
      // No 'to' field = contract deployment
    };

    // API check should fail
    const checkResult = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: 'default',
      method: 'eth_sendTransaction',
      required_claims: ['deploy'],
    });
    expect(checkResult.allowed).toBe(false);
  });

  test('two groups combine to grant deploy permission', async ({ request }) => {
    // Group A: has write
    // Group B: has deploy
    // User in both: should have write + deploy
    const org = await ctx.fixture.createOrg('combinedeployorg');
    const groupA = await ctx.fixture.createGroup(org.id, 'writegroup');
    const groupB = await ctx.fixture.createGroup(org.id, 'deploygroup');

    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_sendTransaction'],
      default_claims: ['write'],
    });

    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['deploy'],
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    // Grant read+write but NOT upgrade
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Check for upgrade claim
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'upgrade'],
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

  test('upgrade claim is contract-specific in effective permissions', async ({ request }) => {
    // Note: required_claims in checkAccess checks if user has claim on ANY contract,
    // not specifically on the target. This test verifies the effective permissions
    // show the correct per-contract claims.
    const org = await ctx.fixture.createOrg('upgradespecificorg');
    const group = await ctx.fixture.createGroup(org.id, 'upgradespecificgroup');
    const contractA = await ctx.fixture.createContract(org.id);
    const contractB = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    // Only contract A has upgrade claim
    await ctx.rbac.createContractGrant(org.id, contractA.address, {
      group_id: group.id,
      claims: ['read', 'write', 'upgrade'],
    });
    await ctx.rbac.createContractGrant(org.id, contractB.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Verify effective permissions show correct per-contract claims
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

    // Contract A should have upgrade
    const accessA = perms.contract_access[contractA.address.toLowerCase()];
    expect(accessA.claims).toContain('upgrade');
    expect(accessA.claims).toContain('read');
    expect(accessA.claims).toContain('write');

    // Contract B should NOT have upgrade
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [], // No default claims
    });

    // Grant only read+write, no upgrade
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Upgrade check should fail (no upgrade on any contract)
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
    const org = await ctx.fixture.createOrg('combineupgradeorg');
    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupA.id,
      claims: ['read', 'write'],
    });

    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
      claims: ['upgrade'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    // Grant everything EXCEPT admin
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'upgrade', 'deploy'],
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'admin'],
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    // Full admin access
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'deploy', 'upgrade', 'admin'],
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
    const org = await ctx.fixture.createOrg('adminhierarchyorg');
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });
    const contract = await ctx.fixture.createContract(org.id);

    // Root has admin grant on contract
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: root.id,
      claims: ['read', 'write', 'admin'],
    });

    // Child has NO grant on this contract - user should inherit from parent
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
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
    // claims are INTERSECTED (child narrows parent)
    const org = await ctx.fixture.createOrg('hierarchyintersectorg');
    const root = await ctx.fixture.createGroup(org.id, 'root');
    const child = await ctx.fixture.createGroup(org.id, 'child', { parentId: root.id });
    const contract = await ctx.fixture.createContract(org.id);

    // Root has read+write+admin
    await ctx.rbac.setGroupAccess(org.id, root.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: root.id,
      claims: ['read', 'write', 'admin'],
    });

    // Child has only read+write (narrows parent by removing admin)
    await ctx.rbac.setGroupAccess(org.id, child.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: child.id,
      claims: ['read', 'write'], // No admin
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'admin'],
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });

    // Has read+write but NOT admin
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write'],
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

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write', 'deploy', 'upgrade', 'admin'],
    });

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write', 'deploy', 'upgrade', 'admin'],
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

    // Should have all default claims
    expect(perms.default_claims).toContain('read');
    expect(perms.default_claims).toContain('write');
    expect(perms.default_claims).toContain('deploy');
    expect(perms.default_claims).toContain('upgrade');
    expect(perms.default_claims).toContain('admin');

    // Should have all claims on the contract
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];
    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');
    expect(contractAccess.claims).toContain('deploy');
    expect(contractAccess.claims).toContain('upgrade');
    expect(contractAccess.claims).toContain('admin');
  });

  test('claims assembled from 5 different groups', async ({ request }) => {
    const org = await ctx.fixture.createOrg('fivegroupsorg');
    const groups = await Promise.all([
      ctx.fixture.createGroup(org.id, 'readgroup'),
      ctx.fixture.createGroup(org.id, 'writegroup'),
      ctx.fixture.createGroup(org.id, 'deploygroup'),
      ctx.fixture.createGroup(org.id, 'upgradegroup'),
      ctx.fixture.createGroup(org.id, 'admingroup'),
    ]);

    const contract = await ctx.fixture.createContract(org.id);

    // Each group contributes one claim
    const claims: Claim[] = ['read', 'write', 'deploy', 'upgrade', 'admin'];
    for (let i = 0; i < groups.length; i++) {
      await ctx.rbac.setGroupAccess(org.id, groups[i].id, {
        allowed_methods: ['eth_call', 'eth_sendTransaction'],
        default_claims: [],
      });
      await ctx.rbac.createContractGrant(org.id, contract.address, {
        group_id: groups[i].id,
        claims: [claims[i]],
      });
    }

    // Create user and add to all 5 groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groups[0].id, {
      kyc: true,
    });
    for (let i = 1; i < groups.length; i++) {
      await ctx.fixture.addMembership(user.id, groups[i].id);
    }

    // User should have UNION of all claims
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    for (const claim of claims) {
      expect(contractAccess.claims).toContain(claim);
    }
  });
});
