/**
 * Security Tests: Historical State Query Blocking
 *
 * Historical state queries allow reading blockchain state at specific past blocks.
 * This can be used for privacy attacks (e.g., tracking address balances over time).
 * The proxy should block queries with specific block numbers or hashes.
 */

import { test, expect } from '@playwright/test';

const API_URL = process.env.API_URL || 'http://localhost:8080';
const MOCK_TOKEN = 'mock.did:security:historical-state-test';

async function setupUser(request: any) {
  await request.put(`${API_URL}/api/v1/users/${encodeURIComponent('did:security:historical-state-test')}`, {
    data: { kyc: true }
  });

  const orgsResp = await request.get(`${API_URL}/api/v1/orgs`);
  const orgs = await orgsResp.json();
  const defaultOrg = orgs.find((o: any) => o.slug === 'default');
  if (defaultOrg) {
    const groupsResp = await request.get(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups`);
    const groups = await groupsResp.json();
    const defaultGroup = groups.find((g: any) => g.slug === 'default-users');
    if (defaultGroup) {
      await request.post(
        `${API_URL}/api/v1/orgs/${defaultOrg.id}/users/${encodeURIComponent('did:security:historical-state-test')}/memberships`,
        { data: { group_id: defaultGroup.id } }
      );
    }
  }
}

async function rpcCall(request: any, method: string, params: any[] = []) {
  const resp = await request.post(`${API_URL}/`, {
    headers: {
      'Authorization': `Bearer ${MOCK_TOKEN}`,
      'Content-Type': 'application/json'
    },
    data: {
      jsonrpc: '2.0',
      method,
      params,
      id: 1
    }
  });
  return {
    status: resp.status(),
    body: await resp.json().catch(() => resp.text())
  };
}

const TEST_ADDRESS = '0x' + '1'.repeat(40);
const HISTORICAL_BLOCK = '0x100';
const BLOCK_HASH = '0x' + 'a'.repeat(64);

test.describe('eth_call Historical State Blocking', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('HIST-001: eth_call with "latest" is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'latest'
    ]);

    // Should not be blocked (might fail for other reasons)
    expect(result.status).not.toBe(403);
  });

  test('HIST-002: eth_call with "pending" is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'pending'
    ]);

    expect(result.status).not.toBe(403);
  });

  test('HIST-003: eth_call with "safe" is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'safe'
    ]);

    // Should not be blocked
    expect(result.status).not.toBe(403);
  });

  test('HIST-004: eth_call with "finalized" is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'finalized'
    ]);

    expect(result.status).not.toBe(403);
  });

  test('HIST-005: eth_call with block number is BLOCKED', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      HISTORICAL_BLOCK
    ]);

    expect(result.status).toBe(403);
    expect(result.body.error).toContain('historical');
  });

  test('HIST-006: eth_call with block hash is BLOCKED', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      { blockHash: BLOCK_HASH }
    ]);

    // Block hash counts as historical
    expect(result.status).toBe(403);
  });

  test('HIST-007: eth_call with no block param defaults to latest', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' }
    ]);

    // Should default to "latest" and be allowed
    expect(result.status).not.toBe(403);
  });
});

test.describe('eth_getStorageAt Historical State Blocking', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('HIST-008: eth_getStorageAt with "latest" is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getStorageAt', [
      TEST_ADDRESS,
      '0x0',
      'latest'
    ]);

    expect(result.status).not.toBe(403);
  });

  test('HIST-009: eth_getStorageAt with block number is BLOCKED', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getStorageAt', [
      TEST_ADDRESS,
      '0x0',
      HISTORICAL_BLOCK
    ]);

    expect(result.status).toBe(403);
    expect(result.body.error).toContain('historical');
  });

  test('HIST-010: eth_getStorageAt with decimal block number', async ({ request }) => {
    // Some clients might send decimal instead of hex
    const result = await rpcCall(request, 'eth_getStorageAt', [
      TEST_ADDRESS,
      '0x0',
      '256'  // Same as 0x100
    ]);

    // Should be treated as historical
    expect(result.status).toBe(403);
  });
});

test.describe('Other Methods with Block Parameters', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('HIST-011: eth_getBalance with historical block', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getBalance', [
      TEST_ADDRESS,
      HISTORICAL_BLOCK
    ]);

    // Document current behavior - might or might not be blocked
    console.log(`eth_getBalance with historical block: status=${result.status}`);
    // TODO: If this returns 200, it's a privacy gap
  });

  test('HIST-012: eth_getCode with historical block', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getCode', [
      TEST_ADDRESS,
      HISTORICAL_BLOCK
    ]);

    console.log(`eth_getCode with historical block: status=${result.status}`);
  });

  test('HIST-013: eth_getTransactionCount with historical block', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getTransactionCount', [
      TEST_ADDRESS,
      HISTORICAL_BLOCK
    ]);

    console.log(`eth_getTransactionCount with historical block: status=${result.status}`);
  });
});

test.describe('Block Parameter Variations', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('HIST-014: Block 0x0 (genesis) is historical', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      '0x0'
    ]);

    expect(result.status).toBe(403);
  });

  test('HIST-015: Block 0x1 is historical', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      '0x1'
    ]);

    expect(result.status).toBe(403);
  });

  test('HIST-016: "earliest" tag is historical', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'earliest'
    ]);

    // "earliest" = block 0, but it's a named tag
    // Current implementation treats named tags as OK
    // This documents the behavior
    console.log(`eth_call with "earliest": status=${result.status}`);
  });

  test('HIST-017: Empty string block param', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      ''
    ]);

    // Should default to latest
    expect(result.status).not.toBe(403);
  });

  test('HIST-018: null block param', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      null
    ]);

    // Should default to latest
    expect(result.status).not.toBe(403);
  });

  test('HIST-019: Very large block number', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      '0xffffffffffffffff'  // Max uint64
    ]);

    // Future block numbers are still "historical" (specific vs current)
    expect(result.status).toBe(403);
  });
});

test.describe('Case Sensitivity in Block Tags', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('HIST-020: "LATEST" (uppercase) is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'LATEST'
    ]);

    // Should be case-insensitive
    expect(result.status).not.toBe(403);
  });

  test('HIST-021: "Latest" (mixed case) is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'Latest'
    ]);

    expect(result.status).not.toBe(403);
  });

  test('HIST-022: "PENDING" (uppercase) is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      'PENDING'
    ]);

    expect(result.status).not.toBe(403);
  });
});
