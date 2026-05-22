import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../helpers/test-context.js';
import { makeRPCRequest } from '../helpers/auth.js';

// Multicall3 is deployed at the same address on all EVM chains
const MULTICALL3_ADDRESS = '0xcA11bde05977b3631167028862bE2a173976CA11';

// Use the default org since RPC handler uses default org
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

test.describe('Multicall Blocking', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  async function createUserWithEthCallPermission(request: Parameters<typeof ctx.fixture.createUserWithMembership>[0]) {
    const group = await ctx.fixture.createGroup(DEFAULT_ORG_ID, 'multicallgroup');

    await ctx.rbac.setGroupAccess(DEFAULT_ORG_ID, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      claims: ['deploy'], // deploy needed for unregistered contract access
    });

    const { token } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
      keepDefaultMembership: false,
    });

    return token;
  }

  test('blocks eth_call to Multicall3 address', async ({ request }) => {
    const token = await createUserWithEthCallPermission(request);

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: MULTICALL3_ADDRESS,
        data: '0x82ad56cb', // aggregate3 selector
      },
      'latest',
    ]);

    // Multicall block is part of RBAC; opaque 404 (privacy-by-default).
    expect(status).toBe(404);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('method not found');
  });

  test('blocks eth_call to Multicall3 address (lowercase)', async ({ request }) => {
    const token = await createUserWithEthCallPermission(request);

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: MULTICALL3_ADDRESS.toLowerCase(),
        data: '0x82ad56cb',
      },
      'latest',
    ]);

    // Multicall block is part of RBAC; opaque 404 (privacy-by-default).
    expect(status).toBe(404);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('method not found');
  });

  test('eth_call to non-Multicall unregistered address is denied (private-by-default)', async ({ request }) => {
    const token = await createUserWithEthCallPermission(request);

    // Use a regular unregistered address (e.g., WETH on mainnet). After RD-855
    // (commit 1ba8da5), all unregistered addresses are denied at the RPC layer
    // regardless of claims. This test now asserts that denial — the multicall
    // block above is a *separate* mechanism from the all-private rule.
    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        data: '0x06fdde03', // name() selector
      },
      'latest',
    ]);

    expect(status).toBe(404); // opaque RBAC denial
    expect(body).toHaveProperty('error');
  });

  test('allows eth_getBalance even with Multicall3 as address param', async ({ request }) => {
    const token = await createUserWithEthCallPermission(request);

    // eth_getBalance takes address as first param, not in call object
    // This should NOT be blocked - only eth_call to Multicall3 is blocked.
    // RD-877: pass the org explicitly — caller has no default-org membership
    // and the implicit fallback on `/` was removed.
    const { status, body } = await makeRPCRequest(
      request,
      token,
      'eth_getBalance',
      [MULTICALL3_ADDRESS, 'latest'],
      DEFAULT_ORG_ID,
    );

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
    expect(body).toHaveProperty('result');
  });
});
