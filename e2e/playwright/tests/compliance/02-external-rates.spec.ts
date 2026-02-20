import { test, expect } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

test.describe('External Rates API', () => {
  let apiKey: string;
  let apiKeyId: string;

  test.beforeAll(async ({ request }) => {
    // Create an API key for testing
    const response = await request.post(`${ADMIN_URL}/api/v1/admin/compliance/api-keys`, {
      data: { name: 'E2E Test Key' },
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
  });

  test('PUT /external/rates without auth returns 401', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/ethereum`, {
      data: { price: 2500 },
    });
    expect(response.status()).toBe(401);
  });

  test('PUT /external/rates with invalid key returns 401', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/ethereum`, {
      headers: { Authorization: 'Bearer ppk_invalidkey123456' },
      data: { price: 2500 },
    });
    expect(response.status()).toBe(401);
  });

  test('PUT /external/rates for nonexistent token returns 404', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/nonexistent-token`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { price: 100 },
    });
    expect(response.status()).toBe(404);
  });

  test('PUT /external/rates with bad price returns 400', async ({ request }) => {
    const response = await request.put(`${ADMIN_URL}/api/v1/external/rates/ethereum`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: { price: -100 },
    });
    expect(response.status()).toBe(400);
  });

  test('API key CRUD lifecycle', async ({ request }) => {
    // List keys
    const listResponse = await request.get(`${ADMIN_URL}/api/v1/admin/compliance/api-keys`);
    expect(listResponse.status()).toBe(200);
    const listBody = await listResponse.json();
    expect(listBody.data.length).toBeGreaterThanOrEqual(1);

    // Create another key
    const createResponse = await request.post(`${ADMIN_URL}/api/v1/admin/compliance/api-keys`, {
      data: { name: 'Temp Key', expires_in_days: 1 },
    });
    expect(createResponse.status()).toBe(201);
    const created = await createResponse.json();
    expect(created.key).toMatch(/^ppk_/);
    expect(created.expires_at).toBeDefined();

    // Revoke it
    const revokeResponse = await request.delete(`${ADMIN_URL}/api/v1/admin/compliance/api-keys/${created.id}`);
    expect(revokeResponse.status()).toBe(200);

    // Verify revoked key is rejected
    const usageResponse = await request.put(`${ADMIN_URL}/api/v1/external/rates/ethereum`, {
      headers: { Authorization: `Bearer ${created.key}` },
      data: { price: 999 },
    });
    expect(usageResponse.status()).toBe(401);
  });
});
