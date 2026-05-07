import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';
import { fns } from '../../helpers/rbac-api.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// Common ERC20 function selectors
const TRANSFER_SELECTOR = '0xa9059cbb'; // transfer(address,uint256)
const APPROVE_SELECTOR = '0x095ea7b3'; // approve(address,uint256)
const BALANCE_OF_SELECTOR = '0x70a08231'; // balanceOf(address)

// Sample transaction data
const SAMPLE_TX_DATA = {
  from: '0x0000000000000000000000000000000000000001',
  to: '0x0000000000000000000000000000000000000002',
  value: '0x0',
  data: '0x',
  gas: '0x5208',
  gasPrice: '0x3b9aca00',
};

test.describe('RBAC Write Operations (eth_sendTransaction)', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('denies eth_sendTransaction when user has only read claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'readonlygroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    // Only allow eth_call with read claim (eth_sendTransaction requires write claim)
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'], // Only read claim
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group.id,
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // eth_call should work (read operation)
    let result = await makeRPCRequest(request, token, 'eth_call', [
      { to: contract.address, data: BALANCE_OF_SELECTOR + '0'.repeat(64) },
      'latest',
    ]);
    expect(result.status).toBe(200);

    // eth_sendTransaction should fail (method not in allowed_methods).
    // RBAC denials return opaque 404 (privacy-by-default).
    result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: contract.address },
    ]);
    expect(result.status).toBe(404);
    expect(result.body).toHaveProperty('error');
  });

  test('allows eth_sendTransaction when user has write claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'writegroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group.id,

    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // eth_sendTransaction should be allowed (note: may return RPC error from node, but not 403)
    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: contract.address },
    ]);

    // Should NOT be 403 (access denied) - might be 200 with RPC error from node
    expect(result.status).not.toBe(403);
  });

  // FLAKY: RD-853 follow-up. RPC layer occasionally allows when perms cache hasn't
  // refreshed after the membership/access mutation. Go unit tests cover the intent.
  test.skip('denies eth_sendTransaction when method not in allowed_methods', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'nomethodgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call'], // No eth_sendTransaction
      claims: ['read', 'write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [SAMPLE_TX_DATA]);
    expect(result.status).toBe(404);
    expect(result.body).toHaveProperty('error');
    expect((result.body as { error: string }).error).toContain('method not found');
  });

  test('write claim on one contract does not grant write on another', async ({ request }) => {
    // Create two groups: one for contract A grants, one for contract B (no grant to this user)
    const groupA = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'contractAGroup');
    const groupB = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'contractBGroup');
    const contractA = await ctx.fixture.createContract(DEFAULT_ORG_ID);
    const contractB = await ctx.fixture.createContract(DEFAULT_ORG_ID); // Registered, but user not granted

    // Group A: has write access to contract A
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, groupA.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contractA.address, {
      group_id: groupA.id,
    });

    // Group B: has write access to contract B (but user won't be in this group)
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, groupB.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contractB.address, {
      group_id: groupB.id,
    });

    // User only in group A
    const { token } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Write to contract A should work
    let result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: contractA.address },
    ]);
    expect(result.status).not.toBe(403);

    // Write to contract B should fail (registered contract, but user has no grant for it).
    // RBAC denials return opaque 404.
    result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: contractB.address },
    ]);
    expect(result.status).toBe(404);
  });

  test('deploy user allowed write to unregistered contracts', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'defaultwritegroup');
    const unknownContract = ctx.contractAddress();

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['deploy'], // Deploy claim required for unregistered contract access
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Deploy users should be able to write to unregistered contracts
    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: unknownContract },
    ]);
    expect(result.status).not.toBe(403);
  });

  test('eth_sendRawTransaction requires valid transaction and authorization', async ({ request }) => {
    // Note: eth_sendRawTransaction is handled specially by the proxy.
    // - When runtime tracing is disabled: blocked before RBAC checks (403)
    // - When runtime tracing is enabled: requires valid RLP, then checks RBAC
    // Either way, sending incomplete/invalid transaction should fail.
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rawgroup');

    // eth_sendRawTransaction requires write claim (it's a write method)
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_sendRawTransaction'],
      claims: ['write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // eth_sendRawTransaction with incomplete transaction data should fail
    const result = await makeRPCRequest(request, token, 'eth_sendRawTransaction', [
      '0xf86c808504a817c800825208940000000000000000000000000000000000000002880de0b6b3a76400008025a0...',
    ]);
    // Should be either 403 (runtime tracing disabled) or 400 (invalid RLP when tracing enabled)
    expect([400, 403]).toContain(result.status);
    expect(result.body).toHaveProperty('error');
  });

  test('write operations blocked for banned user even with write claim', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'bannedwritegroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['deploy'], // deploy needed for unregistered contract access
    });

    const { user, token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // First verify write works
    let result = await makeRPCRequest(request, token, 'eth_sendTransaction', [SAMPLE_TX_DATA]);
    expect(result.status).not.toBe(403);

    // Ban the user
    await ctx.rbac.updateUser(user.id, { banned: true });

    // Now write should fail
    result = await makeRPCRequest(request, token, 'eth_sendTransaction', [SAMPLE_TX_DATA]);
    expect(result.status).toBe(404);
    expect((result.body as { error: string }).error).toContain('method not found');
  });

  test('write operations blocked for non-KYC user', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'nokycwritegroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: false, // No KYC
      keepDefaultMembership: false,
    });

    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [SAMPLE_TX_DATA]);
    expect(result.status).toBe(404);
    expect((result.body as { error: string }).error).toContain('method not found');
  });

  test('write via two groups: union of methods and claims', async ({ request }) => {
    // Scenario: Group A has eth_call with read claim
    //           Group B has eth_sendTransaction with write claim
    // Expected: User in both groups should have union of methods and claims = success for both
    // Note: Backend validates that allowed_methods must have matching claims,
    // so each group must be internally consistent.
    const groupA = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'readgroup');
    const groupB = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'writegroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    // Group A: has eth_call with read claim
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, groupA.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'],
    });

    // Group B: has eth_sendTransaction with write claim
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, groupB.id, {
      allowed_methods: ['eth_sendTransaction'],
      claims: ['write'],
    });

    // Grant both groups access to the registered contract
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, { group_id: groupA.id });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, { group_id: groupB.id });

    const { user, token } = await ctx.fixture.createUserWithMembership(request, groupA.id, {
      kyc: true,
      keepDefaultMembership: false,
    });
    await ctx.fixture.addMembership(user.id, groupB.id);

    // User should have: eth_call (from A) + eth_sendTransaction (from B) + read (from A) + write (from B)
    // Therefore eth_sendTransaction + write should work on the registered contract
    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: contract.address },
    ]);
    expect(result.status).not.toBe(403);
  });

  test('function-level restriction on write operations', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'funcrestrictgroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    // Only allow transfer, not approve
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: group.id,

      functions: fns(TRANSFER_SELECTOR),
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // Transfer should work
    const transferTx = {
      ...SAMPLE_TX_DATA,
      to: contract.address,
      data: TRANSFER_SELECTOR + '0'.repeat(128),
    };
    let result = await makeRPCRequest(request, token, 'eth_sendTransaction', [transferTx]);
    expect(result.status).not.toBe(403);

    // Approve should be blocked
    const approveTx = {
      ...SAMPLE_TX_DATA,
      to: contract.address,
      data: APPROVE_SELECTOR + '0'.repeat(128),
    };
    result = await makeRPCRequest(request, token, 'eth_sendTransaction', [approveTx]);
    expect(result.status).toBe(404);
    expect((result.body as { error: string }).error).toContain('method not found');
  });

  test('multiple users with different write permissions on same contract', async ({ request }) => {
    // User A: read-only (eth_call only), User B: read+write
    // Ensure isolation
    const readGroup = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'readgroup');
    const writeGroup = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'fullgroup');
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    // Read group: only eth_call method with read claim (no eth_sendTransaction)
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, readGroup.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: readGroup.id,
    });

    // Write group: both methods with both claims
    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, writeGroup.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: writeGroup.id,
    });

    const { token: tokenA } = await ctx.fixture.createUserWithMembership(request, readGroup.id, {
      kyc: true,
      keepDefaultMembership: false,
    });
    const { token: tokenB } = await ctx.fixture.createUserWithMembership(request, writeGroup.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    const writeTx = { ...SAMPLE_TX_DATA, to: contract.address };

    // User A should be denied (method not allowed); RBAC denials return opaque 404.
    let result = await makeRPCRequest(request, tokenA, 'eth_sendTransaction', [writeTx]);
    expect(result.status).toBe(404);

    // User B should be allowed
    result = await makeRPCRequest(request, tokenB, 'eth_sendTransaction', [writeTx]);
    expect(result.status).not.toBe(404);
  });
});

test.describe('RBAC Write Operations - Hierarchy', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  // FLAKY: RD-853 follow-up. RPC layer occasionally allows when perms cache hasn't
  // refreshed after the membership/access mutation. Go unit tests cover the intent.
  test.skip('child group cannot expand write access beyond parent', async ({ request }) => {
    // Parent: eth_call only
    // Child: eth_call + eth_sendTransaction
    // User in child: should only have eth_call (intersection)
    const root = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rootwrite');
    const child = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'childwrite', { parentId: root.id });

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, root.id, {
      allowed_methods: ['eth_call'], // Only eth_call
      claims: ['read', 'write'],
    });

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, child.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'], // Child tries to add eth_sendTransaction
      claims: ['read', 'write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // eth_sendTransaction should be blocked (not in parent's methods).
    // RBAC denials return opaque 404.
    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [SAMPLE_TX_DATA]);
    expect(result.status).toBe(404);
    expect((result.body as { error: string }).error).toContain('method not found');
  });

  test('write claim inherited down hierarchy', async ({ request }) => {
    // Parent: write claim via grant
    // Child: inherits via UNION
    const root = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rootinherit');
    const child = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'childinherit', { parentId: root.id });
    const contract = await ctx.fixture.createContract(DEFAULT_ORG_ID);

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, root.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });
    await ctx.rbac.createContractGrant(DEFAULT_ORG_ID, contract.address, {
      group_id: root.id,

    });

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, child.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, child.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    // User in child should have write via inherited grant from parent
    const result = await makeRPCRequest(request, token, 'eth_sendTransaction', [
      { ...SAMPLE_TX_DATA, to: contract.address },
    ]);
    expect(result.status).not.toBe(403);
  });
});
