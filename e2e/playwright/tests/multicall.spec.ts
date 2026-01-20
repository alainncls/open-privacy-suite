import { test, expect } from '@playwright/test';
import { TestContext } from '../helpers/test-context.js';
import { makeRPCRequest } from '../helpers/auth.js';

// Multicall3 is deployed at the same address on all EVM chains
const MULTICALL3_ADDRESS = '0xcA11bde05977b3631167028862bE2a173976CA11';

test.describe('Multicall Blocking', () => {
  let ctx: TestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new TestContext();
    await ctx.cleanup(request);
    // Create policy allowing eth_call
    await ctx.createPolicy(request, {
      kyc: true,
      allowMethods: ['eth_call', 'eth_getBalance'],
    });
  });

  test.afterEach(async ({ request }) => {
    await ctx.cleanup(request);
  });

  test('blocks eth_call to Multicall3 address', async ({ request }) => {
    const token = await ctx.getToken(request);

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: MULTICALL3_ADDRESS,
        data: '0x82ad56cb', // aggregate3 selector
      },
      'latest',
    ]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('multicall not allowed');
  });

  test('blocks eth_call to Multicall3 address (lowercase)', async ({ request }) => {
    const token = await ctx.getToken(request);

    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: MULTICALL3_ADDRESS.toLowerCase(),
        data: '0x82ad56cb',
      },
      'latest',
    ]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('multicall not allowed');
  });

  test('allows eth_call to non-Multicall address', async ({ request }) => {
    const token = await ctx.getToken(request);

    // Use a regular address (e.g., WETH on mainnet)
    const { status, body } = await makeRPCRequest(request, token, 'eth_call', [
      {
        to: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        data: '0x06fdde03', // name() selector
      },
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
  });

  test('allows eth_getBalance even with Multicall3 as address param', async ({ request }) => {
    const token = await ctx.getToken(request);

    // eth_getBalance takes address as first param, not in call object
    // This should NOT be blocked - only eth_call to Multicall3 is blocked
    const { status, body } = await makeRPCRequest(request, token, 'eth_getBalance', [
      MULTICALL3_ADDRESS,
      'latest',
    ]);

    expect(status).toBe(200);
    expect(body).toHaveProperty('jsonrpc', '2.0');
    expect(body).toHaveProperty('result');
  });
});
