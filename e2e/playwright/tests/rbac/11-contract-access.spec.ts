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

  test('allows contract with grant via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractalloworg');
    const group = await ctx.fixture.createGroup(org.id, 'contractallowgroup');
    const contract = await ctx.fixture.createContract(org.id);

    // Grant the group access to this contract
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      
    });

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Read claim required for eth_call
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract.address,
      required_claims: ['read'],
    });

    expect(result.allowed).toBe(true);
    expect(result.claims).toContain('read');
  });

  test('denies registered contract without explicit grant', async ({ request }) => {
    const org = await ctx.fixture.createOrg('contractdenyorg');
    const group = await ctx.fixture.createGroup(org.id, 'contractdenygroup');
    const grantedContract = await ctx.fixture.createContract(org.id);
    const ungrantedContract = await ctx.fixture.createContract(org.id); // Register but don't grant

    // Grant the group access to only one contract
    await ctx.rbac.createContractGrant(org.id, grantedContract.address, {
      group_id: group.id,
    });

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Read claim required for eth_call
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Access to registered contract without explicit grant should fail
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: ungrantedContract.address,
      required_claims: ['read'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('contract access denied');
  });

  test('deploy user allowed access to unregistered contracts', async ({ request }) => {
    const org = await ctx.fixture.createOrg('defaultclaimsorg');
    const group = await ctx.fixture.createGroup(org.id, 'defaultclaimsgroup');
    const unknownContract = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['deploy'], // Deploy claim expands to deploy+read+write; allows unregistered access
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: unknownContract,
      required_claims: ['read'],
    });

    expect(result.allowed).toBe(true);
  });

  test('read-only user denied access to unregistered contracts', async ({ request }) => {
    const org = await ctx.fixture.createOrg('readonlyunregorg');
    const group = await ctx.fixture.createGroup(org.id, 'readonlyunreggroup');
    const unknownContract = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Read-only — no deploy/admin
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: unknownContract,
      required_claims: ['read'],
    });

    // Read-only users can't access unregistered contracts
    expect(result.allowed).toBe(false);
  });

  test('admin user allowed access to unregistered contracts', async ({ request }) => {
    const org = await ctx.fixture.createOrg('adminunregorg');
    const group = await ctx.fixture.createGroup(org.id, 'adminunreggroup');
    const unknownContract = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['admin'], // Admin claim expands to all claims; allows unregistered access
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: unknownContract,
      required_claims: ['read'],
    });

    expect(result.allowed).toBe(true);
  });

  test('allows method without contract address', async ({ request }) => {
    const org = await ctx.fixture.createOrg('nocontractorg');
    const group = await ctx.fixture.createGroup(org.id, 'nocontractgroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_blockNumber'],
      claims: ['read'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Call without contract address
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_blockNumber',
    });

    expect(result.allowed).toBe(true);
  });

  test('RPC eth_call to contract with grant succeeds', async ({ request }) => {
    const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpccontractgroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    // Grant group access to contract
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group.id,
      
    });

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      { to: contract.address, data: '0x' },
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
  });

  test('RPC eth_call to unregistered contract allowed with deploy claim', async ({ request }) => {
    const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcdefaultgroup');
    const unknownContract = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['deploy'], // Deploy claim required for unregistered contract access
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      { to: unknownContract, data: '0x' },
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
  });

  test('grants for multiple contracts work independently', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multigrantorg');
    const group = await ctx.fixture.createGroup(org.id, 'multigrantgroup');
    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);

    // Grant different claims to different contracts
    await ctx.rbac.createContractGrant(org.id, contract1.address, {
      group_id: group.id,
      
    });
    await ctx.rbac.createContractGrant(org.id, contract2.address, {
      group_id: group.id,
      
    });

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write'],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Test each contract has correct claims
    const result1 = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract1.address,
      required_claims: ['read'],
    });
    expect(result1.allowed).toBe(true);

    const result2 = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: contract2.address,
      required_claims: ['write'],
    });
    expect(result2.allowed).toBe(true);
  });

  test('contract address comparison is case-insensitive', async ({ request }) => {
    const org = await ctx.fixture.createOrg('caseorg');
    const group = await ctx.fixture.createGroup(org.id, 'casegroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      
    });

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Read claim required for eth_call
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    // Request with uppercase address should still work
    const upperAddress = contract.address.toUpperCase().replace('0X', '0x');
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: upperAddress,
      required_claims: ['read'],
    });

    expect(result.allowed).toBe(true);
  });
});
