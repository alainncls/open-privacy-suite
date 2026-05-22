/**
 * Security Tests: Historical State Query Policy
 *
 * Historical state queries allow reading blockchain state at specific past blocks.
 * For anonymous users, these are blocked to prevent privacy attacks (balance tracking).
 * For authenticated users, RBAC already gates which addresses they can query,
 * so blocking by block number is redundant and breaks wallets like MetaMask
 * that query at specific blocks for read consistency.
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';

// Serialize describes in this file: every describe runs its own `setupUser`
// against the same module-scoped USER_DID, and `fullyParallel: true` would
// otherwise race two workers on user-insert → opaque 500 "failed to persist
// user record" in beforeAll. Costs a few seconds per file; gains
// deterministic runs.
test.describe.configure({ mode: 'serial' });

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// User DID for this test suite
const USER_DID = `did:security:historical-state-test-${Date.now()}`;

// JWT token will be set in setupUser
let jwtToken: string;

async function setupUser(request: any) {
  // Step 1: Authenticate first - this creates the user via EnsureUserExists
  jwtToken = await getJWTToken(request, USER_DID);

  // Step 2: Find the user by external ID to get their internal ID
  const usersResp = await request.get(`${API_URL}/api/v1/admin/users`);
  const usersData = await usersResp.json();
  const users = usersData.data;
  const user = users.find((u: any) => u.external_id === USER_DID);
  if (!user) {
    throw new Error(`User not created after auth: ${USER_DID}`);
  }

  // Step 3: Update KYC status using internal ID
  await request.put(`${API_URL}/api/v1/admin/users/${user.id}`, {
    data: { kyc: true }
  });

  // Step 4: Get default org and create/find a group with proper permissions
  const orgsResp = await request.get(`${API_URL}/api/v1/admin/orgs`);
  const orgsData = await orgsResp.json();
  const orgs = orgsData.data;
  const defaultOrg = orgs.find((o: any) => o.slug === 'default');

  if (defaultOrg) {
    // Create a group
    const groupResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`, {
      data: {
        slug: 'security-historical-state',
        name: 'Security Historical State Test',
      }
    });

    let groupId: string | null = null;
    if (groupResp.ok()) {
      const group = await groupResp.json();
      groupId = group.id;
    } else {
      // Group might already exist, find it
      const groupsResp = await request.get(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`);
      const groupsData = await groupsResp.json();
      const groups = groupsData.data.map((g: any) => g.group);
      const existing = groups.find((g: any) => g.slug === 'security-historical-state');
      if (existing) groupId = existing.id;
    }

    if (groupId) {
      // Set group access via separate endpoint
      await request.put(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups/${groupId}/access`, {
        data: {
          allowed_methods: ['eth_call', 'eth_getStorageAt', 'eth_getBalance', 'eth_getCode', 'eth_getTransactionCount'],
          claims: ['deploy'] // deploy needed for unregistered contract access
        }
      });

      // Add user to the group
      await request.post(
        `${API_URL}/api/v1/admin/users/${user.id}/memberships`,
        { data: { org_id: defaultOrg.id, group_id: groupId } }
      );
    }
  }

  // Step 5: Get new JWT token with updated KYC status
  jwtToken = await getJWTToken(request, USER_DID);
}

async function rpcCall(request: any, method: string, params: any[] = []) {
  const resp = await request.post(`${API_URL}/`, {
    headers: {
      'Authorization': `Bearer ${jwtToken}`,
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

// Use a unique address unlikely to be registered by other tests
const TEST_ADDRESS = '0x7777777777777777777777777777777777777777';
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

  test('HIST-005: eth_call with block number is ALLOWED for authenticated users', async ({ request }) => {
    // Authenticated users go through full RBAC which gates address access.
    // Historical block queries are only blocked for anonymous users.
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      HISTORICAL_BLOCK
    ]);

    // Should NOT be blocked — RBAC is the access gate, not the block parameter
    expect(result.status).not.toBe(403);
  });

  test('HIST-006: eth_call with block hash is ALLOWED for authenticated users', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      { blockHash: BLOCK_HASH }
    ]);

    // Should NOT be blocked for authenticated users
    expect(result.status).not.toBe(403);
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

  test('HIST-009: eth_getStorageAt with block number is ALLOWED for authenticated users', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getStorageAt', [
      TEST_ADDRESS,
      '0x0',
      HISTORICAL_BLOCK
    ]);

    // Authenticated users are not blocked by historical check — RBAC gates access
    expect(result.status).not.toBe(403);
  });

  test('HIST-010: eth_getStorageAt with decimal block number is ALLOWED for authenticated users', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getStorageAt', [
      TEST_ADDRESS,
      '0x0',
      '256'  // Same as 0x100
    ]);

    // Authenticated users are not blocked by historical check
    expect(result.status).not.toBe(403);
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

    expect(result.status).toBe(404); // opaque RBAC denial
  });

  test('HIST-015: Block 0x1 is historical', async ({ request }) => {
    const result = await rpcCall(request, 'eth_call', [
      { to: TEST_ADDRESS, data: '0x' },
      '0x1'
    ]);

    expect(result.status).toBe(404); // opaque RBAC denial
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
    expect(result.status).toBe(404); // opaque RBAC denial
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
