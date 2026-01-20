import { test, expect } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';

test.describe('Auth Formats', () => {
  test('auth request returns session and auth_request', async ({ request }) => {
    const response = await request.post(`${PROXY_URL}/auth/request`, {
      headers: { 'Content-Type': 'application/json' },
    });

    expect(response.ok()).toBe(true);
    const body = await response.json();

    expect(body).toHaveProperty('session_id');
    expect(body).toHaveProperty('auth_request');
    expect(typeof body.session_id).toBe('string');
    expect(body.session_id.length).toBeGreaterThan(0);
  });

  test('auth_request JSON is reasonably sized for QR encoding', async ({ request }) => {
    const response = await request.post(`${PROXY_URL}/auth/request`);

    expect(response.ok()).toBe(true);
    const body = await response.json();

    // QR codes can encode up to ~4000 bytes with error correction
    // For reliable scanning, keep under 2000 bytes
    const authRequestJson = JSON.stringify(body.auth_request);
    expect(authRequestJson.length).toBeLessThan(2000);
  });

  // QR code URL generation - needs backend implementation
  test.skip('returns QR code URL for mobile User-Agent', async ({ request }) => {
    const response = await request.post(`${PROXY_URL}/auth/request`, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent':
          'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
      },
    });

    expect(response.ok()).toBe(true);
    const body = await response.json();

    // Expected API: qr_code_url field for mobile clients
    expect(body).toHaveProperty('qr_code_url');
    expect(typeof body.qr_code_url).toBe('string');
    expect(body.qr_code_url).toMatch(/^https?:\/\//);
  });

  // Deeplink generation - needs backend implementation
  test.skip('returns deeplink for web clients', async ({ request }) => {
    const response = await request.post(`${PROXY_URL}/auth/request`, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
    });

    expect(response.ok()).toBe(true);
    const body = await response.json();

    // Expected API: deeplink field for web clients to open wallet app
    expect(body).toHaveProperty('deeplink');
    expect(typeof body.deeplink).toBe('string');
    // Deeplink should use a custom scheme (e.g., privado://)
    expect(body.deeplink).toMatch(/^[a-z]+:\/\//);
  });
});
