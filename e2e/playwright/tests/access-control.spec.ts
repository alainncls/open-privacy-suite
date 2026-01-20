import { test, expect } from '@playwright/test';
import { TestContext } from '../helpers/test-context.js';
import { makeRPCRequest } from '../helpers/auth.js';

test.describe('Access Control', () => {
  let ctx: TestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new TestContext();
    // Clean up any existing policy from previous failed runs
    await ctx.cleanup(request);
  });

  test.afterEach(async ({ request }) => {
    await ctx.cleanup(request);
  });

  test('allows method in whitelist', async ({ request }) => {
    // Create policy with eth_getBalance allowed
    await ctx.createPolicy(request, {
      kyc: true,
      allowMethods: ['eth_getBalance'],
    });

    const token = await ctx.getToken(request);
    const { status, body } = await makeRPCRequest(request, token, 'eth_getBalance', [
      '0x0000000000000000000000000000000000000000',
      'latest',
    ]);

    expect(status).toBe(200);
    // Should get a valid JSON-RPC response
    expect(body).toHaveProperty('jsonrpc', '2.0');
    expect(body).toHaveProperty('result');
  });

  test('denies method not in whitelist', async ({ request }) => {
    // Create policy that only allows eth_blockNumber
    await ctx.createPolicy(request, {
      kyc: true,
      allowMethods: ['eth_blockNumber'],
    });

    const token = await ctx.getToken(request);
    const { status, body } = await makeRPCRequest(request, token, 'eth_sendTransaction', [{}]);

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('not allowed');
  });

  test('denies banned user', async ({ request }) => {
    // Create policy with user banned
    await ctx.createPolicy(request, {
      kyc: true,
      banned: true,
      allowMethods: ['eth_blockNumber'],
    });

    const token = await ctx.getToken(request);
    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('banned');
  });

  test('denies user without KYC', async ({ request }) => {
    // Create policy without KYC
    await ctx.createPolicy(request, {
      kyc: false,
      allowMethods: ['eth_blockNumber'],
    });

    const token = await ctx.getToken(request);
    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('KYC');
  });

  test('denies user without policy', async ({ request }) => {
    // Don't create any policy - user should be denied
    const token = await ctx.getToken(request);
    const { status, body } = await makeRPCRequest(request, token, 'eth_blockNumber');

    expect(status).toBe(403);
    expect(body).toHaveProperty('error');
    expect((body as { error: string }).error).toContain('no policy');
  });
});
