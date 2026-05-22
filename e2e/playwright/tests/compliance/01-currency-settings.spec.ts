import { test, expect } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

// Serialize tests in this file: the global compliance currency is a singleton
// in the DB, and `fullyParallel: true` lets "returns default USD" race
// "changes to EUR and back" — the GET sees EUR mid-cycle and the assertion
// flakes. One worker, in order, makes the swap and reset atomic relative to
// the GET.
test.describe.configure({ mode: 'serial' });

test.describe('Currency Settings', () => {
  test('GET /compliance/currency returns default USD', async ({ request }) => {
    const response = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/currency`);
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.currency).toBe('usd');
    expect(body.all_currencies).toBeDefined();
    expect(body.all_currencies.length).toBeGreaterThanOrEqual(5);
  });

  test('PUT /compliance/currency changes to EUR and back', async ({ request }) => {
    // Change to EUR
    const setResponse = await request.put(`${ADMIN_URL}/api/v1/admin/compliance/currency`, {
      data: { currency: 'eur' },
    });
    expect(setResponse.status()).toBe(200);

    const setBody = await setResponse.json();
    expect(setBody.currency).toBe('eur');

    // Verify it persisted
    const getResponse = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/currency`);
    const getBody = await getResponse.json();
    expect(getBody.currency).toBe('eur');

    // Change back to USD
    const resetResponse = await request.put(`${ADMIN_URL}/api/v1/admin/compliance/currency`, {
      data: { currency: 'usd' },
    });
    expect(resetResponse.status()).toBe(200);
  });

  test('PUT /compliance/currency rejects invalid currency', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/admin/compliance/currency`, {
      data: { currency: 'xyz' },
    });
    expect(response.status()).toBe(400);
  });

  test('system-token-prices includes currency field', async ({ request }) => {
    const response = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/system-token-prices`);
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('currency');
  });
});
