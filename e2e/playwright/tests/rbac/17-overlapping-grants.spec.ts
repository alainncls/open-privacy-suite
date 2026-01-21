import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// Common ERC20 function selectors
const TRANSFER_SELECTOR = '0xa9059cbb'; // transfer(address,uint256)
const APPROVE_SELECTOR = '0x095ea7b3'; // approve(address,uint256)
const BALANCE_OF_SELECTOR = '0x70a08231'; // balanceOf(address)
const ALLOWANCE_SELECTOR = '0xdd62ed3e'; // allowance(address,address)
const TRANSFER_FROM_SELECTOR = '0x23b872dd'; // transferFrom(address,address,uint256)

test.describe('RBAC Overlapping Contract Grants', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('user in 2 groups gets UNION of claims on same contract', async ({ request }) => {
    // Scenario: Group A has read on Contract X, Group B has write on Contract X
    // Expected: User in both groups gets read + write on Contract X
    const org = await ctx.fixture.createOrg('claimunioncontractorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract = await ctx.fixture.createContract(org.id);

    // Group A has ONLY read claim on contract
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupA.id,
      claims: ['read'],
    });

    // Group B has ONLY write claim on contract
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
      claims: ['write'],
    });

    // Create user and add to both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // Verify user has UNION of claims (read + write)
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];
    expect(contractAccess).toBeDefined();
    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');

    // Verify via checkAccess - should allow both read and write claims
    const readResult = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });
    expect(readResult.allowed).toBe(true);

    const writeResult = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['write'],
    });
    expect(writeResult.allowed).toBe(true);

    // Should also allow requiring BOTH claims
    const bothResult = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['read', 'write'],
    });
    expect(bothResult.allowed).toBe(true);
  });

  test('user in 2 groups gets UNION of function selectors on same contract', async ({ request }) => {
    // Scenario: Group A allows transfer, Group B allows approve
    // Expected: User in both groups can call both transfer and approve
    const org = await ctx.fixture.createOrg('funcunionorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract = await ctx.fixture.createContract(org.id);

    // Group A allows only transfer
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupA.id,
      claims: ['read', 'write'],
      functions: [TRANSFER_SELECTOR],
    });

    // Group B allows only approve
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
      claims: ['read', 'write'],
      functions: [APPROVE_SELECTOR],
    });

    // Create user and add to both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // Verify user has UNION of function selectors
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];
    expect(contractAccess).toBeDefined();
    expect(contractAccess.functions).toContain(TRANSFER_SELECTOR);
    expect(contractAccess.functions).toContain(APPROVE_SELECTOR);
  });

  test('user in 2 groups with partial overlap gets full UNION', async ({ request }) => {
    // Scenario: Group A: read+write on C1, read on C2
    //           Group B: write on C2, admin on C3
    // Expected: User gets: read+write on C1, read+write on C2, admin on C3
    const org = await ctx.fixture.createOrg('partialoverlaporg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);
    const contract3 = await ctx.fixture.createContract(org.id);

    // Group A setup
    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: groupA.id,
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: groupA.id,
      claims: ['read'],
    });

    // Group B setup
    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: groupB.id,
      claims: ['write'],
    });
    await ctx.rbac.createContractGrant(org.id, contract3.address, {
      group_id: groupB.id,
      claims: ['admin'],
    });

    // Create user in both groups
    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // Verify permissions
    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

    // Contract 1: read + write (from A only)
    const c1Access = perms.contract_access[contract1.address.toLowerCase()];
    expect(c1Access.claims).toContain('read');
    expect(c1Access.claims).toContain('write');

    // Contract 2: read + write (union of A's read and B's write)
    const c2Access = perms.contract_access[contract2.address.toLowerCase()];
    expect(c2Access.claims).toContain('read');
    expect(c2Access.claims).toContain('write');

    // Contract 3: admin (from B only)
    const c3Access = perms.contract_access[contract3.address.toLowerCase()];
    expect(c3Access.claims).toContain('admin');
  });

  test('overlapping grants with different function restrictions merge correctly', async ({ request }) => {
    // Scenario: Group A: balanceOf + transfer on C
    //           Group B: balanceOf + approve on C
    // Expected: User gets balanceOf + transfer + approve (no duplicates)
    const org = await ctx.fixture.createOrg('funcmergeorg');

    const groupA = await ctx.fixture.createGroup(org.id, 'groupA');
    const groupB = await ctx.fixture.createGroup(org.id, 'groupB');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, groupA.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupA.id,
      claims: ['read', 'write'],
      functions: [BALANCE_OF_SELECTOR, TRANSFER_SELECTOR],
    });

    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
      claims: ['read', 'write'],
      functions: [BALANCE_OF_SELECTOR, APPROVE_SELECTOR],
    });

    const { user } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    // Should have all three functions (union, no duplicates)
    expect(contractAccess.functions).toContain(BALANCE_OF_SELECTOR);
    expect(contractAccess.functions).toContain(TRANSFER_SELECTOR);
    expect(contractAccess.functions).toContain(APPROVE_SELECTOR);
    // Should not have allowance or transferFrom
    expect(contractAccess.functions).not.toContain(ALLOWANCE_SELECTOR);
    expect(contractAccess.functions).not.toContain(TRANSFER_FROM_SELECTOR);
  });

  test('one group with functions=null gives access to all functions', async ({ request }) => {
    // Scenario: Group A: only balanceOf on C
    //           Group B: all functions on C (functions=null)
    // Expected: User gets all functions (null trumps specific list in UNION across sibling groups)
    const org = await ctx.fixture.createOrg('nullfunctionsorg');

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
      functions: [BALANCE_OF_SELECTOR], // Only balanceOf
    });

    await ctx.rbac.setGroupAccess(org.id, groupB.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: groupB.id,
      claims: ['read'],
      // functions not specified = null = all functions allowed
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    // functions should be null (all allowed) because union includes "all"
    // Note: null/undefined in JS maps to no restriction
    expect(contractAccess.functions === null || contractAccess.functions === undefined).toBe(true);
  });

  test('claims escalate through group overlap: read-only becomes read+write', async ({ request }) => {
    // Scenario: User starts with read-only, adding to write group escalates
    const org = await ctx.fixture.createOrg('escalateorg');

    const readGroup = await ctx.fixture.createGroup(org.id, 'readonly');
    const writeGroup = await ctx.fixture.createGroup(org.id, 'writers');
    const contract = await ctx.fixture.createContract(org.id);

    // Read-only group
    await ctx.rbac.setGroupAccess(org.id, readGroup.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: readGroup.id,
      claims: ['read'],
    });

    // Write group
    await ctx.rbac.setGroupAccess(org.id, writeGroup.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: writeGroup.id,
      claims: ['write'],
    });

    // Create user in read-only group
    const { user, did } = await ctx.fixture.createUserWithMembership(request, readGroup.id, {
      kyc: true,
    });

    // Initially should have read but not write
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });
    expect(result.allowed).toBe(true);

    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['write'],
    });
    expect(result.allowed).toBe(false);

    // Add user to write group
    await ctx.fixture.addMembership(user.id, writeGroup.id);

    // Now should have both read and write
    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_sendTransaction',
      target_address: contract.address,
      required_claims: ['write'],
    });
    expect(result.allowed).toBe(true);

    result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read', 'write'],
    });
    expect(result.allowed).toBe(true);
  });

  test('admin grant from one group combines with regular grants', async ({ request }) => {
    // Scenario: Group A: read+write, Group B: admin
    // Expected: User gets read+write+admin
    const org = await ctx.fixture.createOrg('admincomboorg');

    const normalGroup = await ctx.fixture.createGroup(org.id, 'normal');
    const adminGroup = await ctx.fixture.createGroup(org.id, 'admins');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.setGroupAccess(org.id, normalGroup.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: normalGroup.id,
      claims: ['read', 'write'],
    });

    await ctx.rbac.setGroupAccess(org.id, adminGroup.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: adminGroup.id,
      claims: ['admin'],
    });

    const { user, did } = await ctx.fixture.createUserWithMembership(request, normalGroup.id, {
      kyc: true,
    });
    await ctx.fixture.addMembership(user.id, adminGroup.id);

    const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);
    const contractAccess = perms.contract_access[contract.address.toLowerCase()];

    expect(contractAccess.claims).toContain('read');
    expect(contractAccess.claims).toContain('write');
    expect(contractAccess.claims).toContain('admin');
  });

  test('RPC: overlapping grants allow operations via actual RPC calls', async ({ request }) => {
    // Test with actual RPC calls, not just API checks
    const group1 = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcgroup1');
    const group2 = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcgroup2');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    // Group 1: read only
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group1.id, {
      allowed_methods: ['eth_call'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group1.id,
      claims: ['read'],
    });

    // Group 2: also read (overlap) - should still work with union
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group2.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: [],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group2.id,
      claims: ['read'],
    });

    const { user, token } = await ctx.fixture.createUserWithMembership(request, group1.id, {
      kyc: true,
      keepDefaultMembership: false,
    });
    await ctx.fixture.addMembership(user.id, group2.id);

    // Should be able to call the contract (read)
    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      { to: contract.address, data: '0x' },
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
  });
});
