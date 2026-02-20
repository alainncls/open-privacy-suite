import { test, expect } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

const TEST_TOKEN_ADDRESS = '0x1111111111111111111111111111111111111111';
const TEST_SYMBOL = 'TESTBANK';
const TEST_DECIMALS = 8;
const TEST_PRICE = 42.5;
const UPDATED_PRICE = 99.99;

test.describe.serial('External Rates API', () => {
  let apiKey: string;
  let apiKeyId: string;

  test.beforeAll(async ({ request }) => {
    const response = await request.post(`${ADMIN_URL}/api/v1/admin/compliance/api-keys`, {
      data: { name: 'E2E External Rates Test Key' },
    });
    expect(response.status()).toBe(201);

    const body = await response.json();
    apiKey = body.key;
    apiKeyId = body.id;
    expect(apiKey).toMatch(/^ppk_/);
  });

  test.afterAll(async ({ request }) => {
    // Revoke the test API key
    if (apiKeyId) {
      await request.delete(`${ADMIN_URL}/api/v1/admin/compliance/api-keys/${apiKeyId}`);
    }
    // Note: we cannot delete system token prices via API, but E2E environment is ephemeral.
  });

  // ── Auth tests ───────────────────────────────────────────────────────

  test('PUT /external/rates without auth returns 401', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      data: { token_address: TEST_TOKEN_ADDRESS, price: TEST_PRICE, symbol: TEST_SYMBOL, decimals: TEST_DECIMALS },
    });
    expect(response.status()).toBe(401);
  });

  test('PUT /external/rates with invalid key returns 401', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: 'Bearer ppk_invalidkey123456' },
      data: { token_address: TEST_TOKEN_ADDRESS, price: TEST_PRICE, symbol: TEST_SYMBOL, decimals: TEST_DECIMALS },
    });
    expect(response.status()).toBe(401);
  });

  // ── Validation tests ─────────────────────────────────────────────────

  test('PUT /external/rates without token_address returns 400', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { price: TEST_PRICE, symbol: TEST_SYMBOL, decimals: TEST_DECIMALS },
    });
    expect(response.status()).toBe(400);
  });

  test('PUT /external/rates with negative price returns 400', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { token_address: TEST_TOKEN_ADDRESS, price: -10, symbol: TEST_SYMBOL, decimals: TEST_DECIMALS },
    });
    expect(response.status()).toBe(400);
  });

  test('PUT /external/rates with zero price returns 400', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { token_address: TEST_TOKEN_ADDRESS, price: 0, symbol: TEST_SYMBOL, decimals: TEST_DECIMALS },
    });
    expect(response.status()).toBe(400);
  });

  test('PUT /external/rates with invalid address format returns 400', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { token_address: '0xINVALID', price: TEST_PRICE, symbol: TEST_SYMBOL, decimals: TEST_DECIMALS },
    });
    expect(response.status()).toBe(400);
  });

  // ── Create new external token ────────────────────────────────────────

  test('PUT /external/rates creates new external token with 201', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        token_address: TEST_TOKEN_ADDRESS,
        price: TEST_PRICE,
        symbol: TEST_SYMBOL,
        decimals: TEST_DECIMALS,
      },
    });
    expect(response.status()).toBe(201);

    const body = await response.json();
    expect(body.id).toBeTruthy();
    expect(body.token_address).toBe(TEST_TOKEN_ADDRESS);
    expect(body.symbol).toBe(TEST_SYMBOL);
    expect(body.price_fiat).toBe(TEST_PRICE);
    expect(body.source).toBe('external');
  });

  // ── Update existing external token ───────────────────────────────────

  test('PUT /external/rates updates existing external token with 200', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        token_address: TEST_TOKEN_ADDRESS,
        price: UPDATED_PRICE,
      },
    });
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.token_address).toBe(TEST_TOKEN_ADDRESS);
    expect(body.price_fiat).toBe(UPDATED_PRICE);
    expect(body.source).toBe('external');
  });

  // ── Verify via system-token-prices list ──────────────────────────────

  test('system-token-prices list contains the test token', async ({ request }) => {
    const response = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/system-token-prices`);
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.data).toBeInstanceOf(Array);

    const testToken = body.data.find(
      (t: { token_address: string }) => t.token_address === TEST_TOKEN_ADDRESS
    );
    expect(testToken).toBeTruthy();
    expect(testToken.symbol).toBe(TEST_SYMBOL);
    expect(testToken.source).toBe('external');
    expect(testToken.price_fiat).toBe(UPDATED_PRICE);
  });

  // ── CoinGecko protection ─────────────────────────────────────────────

  test('PUT /external/rates cannot override CoinGecko-sourced token', async ({ request }) => {
    // First, find a CoinGecko-sourced token in system prices
    const listResponse = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/system-token-prices`);
    expect(listResponse.status()).toBe(200);

    const listBody = await listResponse.json();
    const coingeckoToken = listBody.data.find(
      (t: { source: string; token_address?: string }) => t.source === 'coingecko' && t.token_address
    );

    if (!coingeckoToken) {
      test.skip();
      return;
    }

    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        token_address: coingeckoToken.token_address,
        price: 1,
      },
    });
    expect(response.status()).toBe(409);
  });

  // ── API key lifecycle ────────────────────────────────────────────────

  test('API key lifecycle: create, use, revoke, verify rejection', async ({ request }) => {
    // Create a temporary key
    const createResponse = await request.post(`${ADMIN_URL}/api/v1/admin/compliance/api-keys`, {
      data: { name: 'Temp Lifecycle Key', expires_in_days: 1 },
    });
    expect(createResponse.status()).toBe(201);

    const created = await createResponse.json();
    expect(created.key).toMatch(/^ppk_/);
    expect(created.expires_at).toBeDefined();

    // Use the key successfully
    const useResponse = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${created.key}` },
      data: {
        token_address: TEST_TOKEN_ADDRESS,
        price: 50,
      },
    });
    expect(useResponse.status()).toBe(200);

    // Revoke the key
    const revokeResponse = await request.delete(`${ADMIN_URL}/api/v1/admin/compliance/api-keys/${created.id}`);
    expect(revokeResponse.status()).toBe(200);

    // Verify the revoked key is rejected
    const rejectedResponse = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${created.key}` },
      data: {
        token_address: TEST_TOKEN_ADDRESS,
        price: 60,
      },
    });
    expect(rejectedResponse.status()).toBe(401);
  });
});
