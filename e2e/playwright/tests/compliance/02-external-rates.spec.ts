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
    // Disable cooldown for E2E tests (default 1440 min would block rapid updates)
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { price_update_cooldown_minutes: 0, max_price_deviation_pct: 500 },
    });

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

  // ── Settings CRUD ───────────────────────────────────────────────────

  test('GET external-rates-settings returns current values', async ({ request }) => {
    const response = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`);
    expect(response.status()).toBe(200);
    const body = await response.json();
    // These were set in beforeAll to permissive values for E2E tests
    expect(typeof body.max_price_deviation_pct).toBe('number');
    expect(typeof body.price_update_cooldown_minutes).toBe('number');
  });

  test('PUT external-rates-settings updates settings', async ({ request }) => {
    // Set cooldown to 0 and deviation to 200 for subsequent tests
    const response = await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { max_price_deviation_pct: 200, price_update_cooldown_minutes: 0 },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.max_price_deviation_pct).toBe(200);
    expect(body.price_update_cooldown_minutes).toBe(0);
  });

  // ── Batch endpoint ─────────────────────────────────────────────────

  test('PUT /external/rates/batch creates multiple tokens', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/batch`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        prices: [
          { token_address: '0x2222222222222222222222222222222222222222', price: 10, symbol: 'BATCH1', decimals: 18 },
          { token_address: '0x3333333333333333333333333333333333333333', price: 20, symbol: 'BATCH2', decimals: 8 },
        ],
      },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.results).toHaveLength(2);
    expect(body.results[0].status).toBe('ok');
    expect(body.results[1].status).toBe('ok');
  });

  test('PUT /external/rates/batch handles partial failures', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/batch`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        prices: [
          { token_address: '0x2222222222222222222222222222222222222222', price: 15 },  // update existing
          { token_address: '0xINVALID', price: 10, symbol: 'BAD', decimals: 18 },      // bad address
        ],
      },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.results).toHaveLength(2);
    expect(body.results[0].status).toBe('ok');
    expect(body.results[1].status).toBe('error');
  });

  test('PUT /external/rates/batch rejects empty array', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/batch`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { prices: [] },
    });
    expect(response.status()).toBe(400);
  });

  // ── Bounds checking ────────────────────────────────────────────────

  test('bounds check: rejects price change exceeding max deviation', async ({ request }) => {
    // Set tight max deviation for this test
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { max_price_deviation_pct: 10 },
    });

    // Try to change BATCH1 price from 15 to 100 (>>10% deviation)
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { token_address: '0x2222222222222222222222222222222222222222', price: 100 },
    });
    expect(response.status()).toBe(422);
    const body = await response.json();
    expect(body.error).toContain('exceeds maximum allowed deviation');

    // Reset deviation to a permissive value
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { max_price_deviation_pct: 500 },
    });
  });

  // ── Cooldown enforcement ───────────────────────────────────────────

  test('cooldown check: rejects rapid price updates', async ({ request }) => {
    // Set 60-minute cooldown
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { price_update_cooldown_minutes: 60 },
    });

    // Try the test token that was just created - it should be in cooldown
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { token_address: '0x2222222222222222222222222222222222222222', price: 16 },
    });
    expect(response.status()).toBe(429);
    const body = await response.json();
    expect(body.error).toContain('cooldown');

    // Reset cooldown to 0 for cleanup
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { price_update_cooldown_minutes: 0 },
    });
  });

  // ── Price change audit log ─────────────────────────────────────────

  test('price change log contains entries', async ({ request }) => {
    const response = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/price-change-log`);
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.data).toBeInstanceOf(Array);
    expect(body.data.length).toBeGreaterThanOrEqual(1);
    // Check structure of first entry
    const entry = body.data[0];
    expect(entry.api_key_name).toBeTruthy();
    expect(entry.token_address).toBeTruthy();
    expect(entry.new_price).toBeGreaterThan(0);
    expect(entry.ip_address).toBeTruthy();
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
