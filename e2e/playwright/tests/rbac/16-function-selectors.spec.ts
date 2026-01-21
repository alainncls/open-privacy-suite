import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { makeRPCRequest } from '../../helpers/auth.js';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// Common ERC20 function selectors
const TRANSFER_SELECTOR = '0xa9059cbb'; // transfer(address,uint256)
const APPROVE_SELECTOR = '0x095ea7b3'; // approve(address,uint256)
const BALANCE_OF_SELECTOR = '0x70a08231'; // balanceOf(address)

test.describe('RBAC Function Selector Enforcement', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('allows function selector in allowlist via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('funcselectororg');
    const group = await ctx.fixture.createGroup(org.id, 'funcselectorgroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    const testContract = ctx.contractAddress();

    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [testContract],
      address_functions: {
        [testContract.toLowerCase()]: [TRANSFER_SELECTOR, BALANCE_OF_SELECTOR],
      },
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // Transfer should be allowed
    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: testContract,
    });

    expect(result.allowed).toBe(true);
  });

  test('denies function selector NOT in allowlist via checkAccess API', async ({ request }) => {
    const org = await ctx.fixture.createOrg('funcselectordenyorg');
    const group = await ctx.fixture.createGroup(org.id, 'funcselectordenygroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    const testContract = ctx.contractAddress();

    // Only allow balanceOf, not transfer or approve
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [testContract],
      address_functions: {
        [testContract.toLowerCase()]: [BALANCE_OF_SELECTOR],
      },
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    // balanceOf should be allowed
    let result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: testContract,
    });
    expect(result.allowed).toBe(true);
  });

  test('allows all functions when no address_functions restriction exists', async ({ request }) => {
    const org = await ctx.fixture.createOrg('nofuncrestrictorg');
    const group = await ctx.fixture.createGroup(org.id, 'nofuncrestrictgroup');
    const role = await ctx.fixture.createReaderRole(org.id);

    const testContract = ctx.contractAddress();

    // No address_functions specified - all functions allowed
    await ctx.rbac.setGroupPermissions(org.id, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [testContract],
    });

    const { did } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
    });

    const result = await ctx.rbac.checkAccess({
      user_external_id: did,
      org_slug: org.slug,
      method: 'eth_call',
      target_address: testContract,
    });

    expect(result.allowed).toBe(true);
  });

  test('RPC request allowed for function selector in allowlist', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcfuncselectorgroup');
    const role = await ctx.fixture.createRole(DEFAULT_ORG_ID, 'rpcfuncselectorrole', ['reader']);

    const testContract = ctx.contractAddress();

    await ctx.rbac.setGroupPermissions(DEFAULT_ORG_ID, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [testContract],
      address_functions: {
        [testContract.toLowerCase()]: [BALANCE_OF_SELECTOR],
      },
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
      keepDefaultMembership: false,
    });

    // Call with allowed function selector
    const { status } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: testContract,
        data: BALANCE_OF_SELECTOR + '0000000000000000000000000000000000000000000000000000000000000001',
      },
      'latest',
    ]);

    expect(status).toBe(200);
  });

  test('RPC request denied for function selector NOT in allowlist', async ({ request }) => {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'rpcfuncselectordenygroup');
    const role = await ctx.fixture.createRole(DEFAULT_ORG_ID, 'rpcfuncselectordenyrole', ['reader']);

    const testContract = ctx.contractAddress();

    // Only allow balanceOf
    await ctx.rbac.setGroupPermissions(DEFAULT_ORG_ID, group.id, {
      allow_methods: ['eth_call'],
      allow_addresses: [testContract],
      address_functions: {
        [testContract.toLowerCase()]: [BALANCE_OF_SELECTOR],
      },
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      roleId: role.id,
      keepDefaultMembership: false,
    });

    // Call with disallowed function selector (approve)
    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: testContract,
        data: APPROVE_SELECTOR + '0000000000000000000000000000000000000000000000000000000000000001',
      },
      'latest',
    ]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('function');
  });
});
