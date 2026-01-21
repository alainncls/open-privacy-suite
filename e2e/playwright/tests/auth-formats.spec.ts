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

  test('auth_request can generate valid iden3comm deeplink', async ({ request }) => {
    const response = await request.post(`${PROXY_URL}/auth/request`);

    expect(response.ok()).toBe(true);
    const body = await response.json();

    // Frontend generates deeplink: iden3comm://?i_m=<base64_encoded_auth_request>
    const authRequestJson = JSON.stringify(body.auth_request);
    const base64Encoded = Buffer.from(authRequestJson).toString('base64');
    const deeplink = `iden3comm://?i_m=${encodeURIComponent(base64Encoded)}`;

    // Verify deeplink format
    expect(deeplink).toMatch(/^iden3comm:\/\/\?i_m=/);

    // Verify the encoded message can be decoded back
    const urlParams = new URLSearchParams(deeplink.split('?')[1]);
    const encodedMessage = urlParams.get('i_m');
    expect(encodedMessage).not.toBeNull();

    const decodedJson = Buffer.from(decodeURIComponent(encodedMessage!), 'base64').toString();
    const decoded = JSON.parse(decodedJson);

    // Verify decoded matches original
    expect(decoded.id).toBe(body.auth_request.id);
    expect(decoded.typ).toBe('application/iden3comm-plain-json');
    expect(decoded.type).toBe('https://iden3-communication.io/authorization/1.0/request');
  });

  test('auth_request contains required iden3comm fields for wallet', async ({ request }) => {
    const response = await request.post(`${PROXY_URL}/auth/request`);

    expect(response.ok()).toBe(true);
    const body = await response.json();
    const authRequest = body.auth_request;

    // Required iden3comm fields
    expect(authRequest).toHaveProperty('id');
    expect(authRequest).toHaveProperty('thid');
    expect(authRequest).toHaveProperty('typ', 'application/iden3comm-plain-json');
    expect(authRequest).toHaveProperty('type', 'https://iden3-communication.io/authorization/1.0/request');
    expect(authRequest).toHaveProperty('from');
    expect(authRequest).toHaveProperty('body');

    // Body should contain callback URL
    expect(authRequest.body).toHaveProperty('callbackUrl');
    expect(authRequest.body.callbackUrl).toMatch(/\/auth\/callback\?session=/);

    // Body should contain reason for user display
    expect(authRequest.body).toHaveProperty('reason');
    expect(typeof authRequest.body.reason).toBe('string');
  });
});
