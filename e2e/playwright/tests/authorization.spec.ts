import { test, expect } from '@playwright/test';
import { makeUnauthenticatedRPCRequest, makeRPCRequest } from '../helpers/auth.js';

test.describe('Authorization', () => {
  test('denies unauthenticated request', async ({ request }) => {
    const { status, body } = await makeUnauthenticatedRPCRequest(request, 'eth_getBalance', ['0x0000000000000000000000000000000000000001', 'latest']);

    // RBAC denials return opaque 404 (privacy-by-default).
    expect(status).toBe(404);
    expect(body).toHaveProperty('error');
  });

  test('denies request with invalid JWT', async ({ request }) => {
    const { status, body } = await makeRPCRequest(request, 'invalid.jwt.token', 'eth_blockNumber');

    expect(status).toBe(401);
    expect(body).toHaveProperty('error');
  });

  test('denies request with malformed Authorization header', async ({ request }) => {
    const response = await request.post('/', {
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'NotBearer sometoken',
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1,
      },
    });

    expect(response.status()).toBe(401);
    const body = await response.json();
    expect(body).toHaveProperty('error');
  });

  test('denies request with empty Authorization header', async ({ request }) => {
    const response = await request.post('/', {
      headers: {
        'Content-Type': 'application/json',
        Authorization: '',
      },
      data: {
        jsonrpc: '2.0',
        method: 'eth_getBalance',
        params: ['0x0000000000000000000000000000000000000001', 'latest'],
        id: 1,
      },
    });

    expect(response.status()).toBe(404);
    const body = await response.json();
    expect(body).toHaveProperty('error');
  });
});
