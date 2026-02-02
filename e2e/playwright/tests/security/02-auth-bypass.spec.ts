/**
 * Security Tests: Authentication Bypass
 *
 * These tests attempt to bypass authentication mechanisms.
 * CRITICAL: Any bypass allows full access to protected resources.
 */

import { test, expect } from '@playwright/test';

const API_URL = process.env.API_URL || 'http://localhost:8080';

test.describe('Authentication Bypass Attempts', () => {

  test('AUTH-001: Request without Authorization header is denied', async ({ request }) => {
    const resp = await request.post(`${API_URL}/`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-002: Request with empty Authorization header is denied', async ({ request }) => {
    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'Authorization': '',
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-003: Request with "Bearer" only (no token) is denied', async ({ request }) => {
    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'Authorization': 'Bearer ',
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-004: Request with malformed JWT is denied', async ({ request }) => {
    const malformedTokens = [
      'invalid',
      'Bearer invalid',
      'eyJhbGciOiJIUzI1NiJ9', // Header only
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0', // Header + payload, no signature
      'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.', // alg:none attack
      '....', // Just dots
      'a.b.c', // Invalid base64
    ];

    for (const token of malformedTokens) {
      const resp = await request.post(`${API_URL}/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        data: {
          jsonrpc: '2.0',
          method: 'eth_blockNumber',
          params: [],
          id: 1
        }
      });

      expect(resp.status()).toBe(401);
    }
  });

  test('AUTH-005: Request with forged JWT signature is denied', async ({ request }) => {
    // Valid-looking JWT with tampered signature
    const forgedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0.INVALID_SIGNATURE';

    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'Authorization': `Bearer ${forgedToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-006: Request with expired JWT is denied', async ({ request }) => {
    // JWT with exp in the past (this is a mock token with expired timestamp)
    // In real scenario, server should reject expired tokens
    const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.dGVzdA';

    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'Authorization': `Bearer ${expiredToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-007: Algorithm confusion attack (alg:none) is rejected', async ({ request }) => {
    // Attempt alg:none attack
    const algNoneToken = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') +
                         '.' +
                         Buffer.from('{"sub":"attacker","exp":9999999999}').toString('base64url') +
                         '.';

    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'Authorization': `Bearer ${algNoneToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-008: JWKS confusion (different kid) is rejected', async ({ request }) => {
    // Token with unknown key ID
    const unknownKidToken = Buffer.from('{"alg":"RS256","typ":"JWT","kid":"unknown-key-id"}').toString('base64url') +
                            '.' +
                            Buffer.from('{"sub":"attacker"}').toString('base64url') +
                            '.fake-signature';

    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'Authorization': `Bearer ${unknownKidToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-009: Case sensitivity in Authorization header', async ({ request }) => {
    // Try lowercase "bearer" instead of "Bearer"
    const resp = await request.post(`${API_URL}/`, {
      headers: {
        'authorization': 'bearer some-token',
        'Content-Type': 'application/json'
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    // Should still be rejected (token is invalid)
    expect(resp.status()).toBe(401);
  });

  test('AUTH-010: Token in query parameter is not accepted', async ({ request }) => {
    const resp = await request.post(`${API_URL}/?token=mock.did:test:user`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-011: Token in request body is not accepted', async ({ request }) => {
    const resp = await request.post(`${API_URL}/`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1,
        token: 'mock.did:test:user'
      }
    });

    expect(resp.status()).toBe(401);
  });

  test('AUTH-012: Multiple Authorization headers are handled safely', async ({ request }) => {
    // This depends on how the server handles multiple headers
    // Should not accept if any header is invalid
    const resp = await request.post(`${API_URL}/`, {
      headers: [
        ['Authorization', 'Bearer invalid1'],
        ['Authorization', 'Bearer invalid2'],
        ['Content-Type', 'application/json']
      ],
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      }
    });

    expect(resp.status()).toBe(401);
  });
});

test.describe('Mock Token Security (Dev Mode)', () => {
  // These tests verify mock token behavior
  // In production, mock tokens should be completely disabled

  test('MOCK-001: Mock token format is validated', async ({ request }) => {
    // Mock tokens must start with "mock." and have a valid DID format
    const invalidMockTokens = [
      'mock',           // No dot
      'mock.',          // Empty DID
      'Mock.did:test',  // Wrong case
      'MOCK.did:test',  // Wrong case
    ];

    for (const token of invalidMockTokens) {
      const resp = await request.post(`${API_URL}/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        data: {
          jsonrpc: '2.0',
          method: 'eth_blockNumber',
          params: [],
          id: 1
        }
      });

      // Should be rejected - either 401 (auth) or 403 (RBAC)
      expect([401, 403]).toContain(resp.status());
    }
  });
});

test.describe('Session Security', () => {

  test('SESSION-001: Session ID enumeration is not possible', async ({ request }) => {
    // Try to access sessions with sequential/predictable IDs
    const predictableIds = [
      '00000000-0000-0000-0000-000000000000',
      '00000000-0000-0000-0000-000000000001',
      '11111111-1111-1111-1111-111111111111',
      'test-session-id',
      '1',
    ];

    for (const id of predictableIds) {
      const resp = await request.get(`${API_URL}/api/v1/auth/session/${id}/status`);

      // Should return 404 (not found) not detailed error
      expect([404, 400]).toContain(resp.status());

      const body = await resp.json().catch(() => ({}));
      // Should not leak info about whether session exists
      expect(body.error).not.toContain('expired');
      expect(body.error).not.toContain('completed');
    }
  });

  test('SESSION-002: OAuth session enumeration is not possible', async ({ request }) => {
    const predictableIds = [
      '00000000-0000-0000-0000-000000000000',
      'test-oauth-session',
    ];

    for (const id of predictableIds) {
      const resp = await request.get(`${API_URL}/oauth/session/${id}/status`);

      expect([404, 400]).toContain(resp.status());
    }
  });
});
