/**
 * Security Tests: Cross-Organization Isolation
 *
 * These tests verify that users in one organization cannot access
 * contracts or data belonging to another organization.
 *
 * CRITICAL: Cross-org leakage is a P0 security issue.
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';
import { randomAddress } from '../../helpers/address.js';

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// Helper to make authenticated RPC call
async function rpcCall(request: any, token: string, method: string, params: any[] = []) {
  const resp = await request.post(`${API_URL}/`, {
    headers: {
      'Authorization': `Bearer ${token}`,
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

async function waitForContractAccess(
  request: any,
  token: string,
  address: string,
  attempts = 12,
  delayMs = 100
) {
  let lastResult: { status: number; body: any } = { status: 0, body: null };

  for (let i = 0; i < attempts; i++) {
    const result = await rpcCall(request, token, 'eth_call', [
      { to: address, data: '0x' },
      'latest'
    ]);
    lastResult = result;

    if (result.status !== 403) {
      return result;
    }

    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  return lastResult;
}

test.describe('Cross-Organization Isolation', () => {
  let orgAId: string;
  let orgBId: string;
  let contractA: string;
  let contractB: string;
  let userAToken: string;
  let userBToken: string;
  let groupAId: string;
  let groupBId: string;
  // Unique ID per test worker - timestamp + random suffix for parallel execution
  let testRunId: string;

  test.beforeAll(async ({ request }) => {
    // Generate unique test run ID inside beforeAll to avoid conflicts with parallel workers
    testRunId = `${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    // Create Organization A - unique per test run
    const orgAResp = await request.post(`${API_URL}/api/v1/admin/orgs`, {
      data: { slug: `security-org-a-${testRunId}`, name: 'Security Test Org A' }
    });
    if (orgAResp.ok()) {
      const orgA = await orgAResp.json();
      orgAId = orgA.id;
    } else {
      throw new Error(`Failed to create org A: ${await orgAResp.text()}`);
    }

    // Create Organization B - unique per test run
    const orgBResp = await request.post(`${API_URL}/api/v1/admin/orgs`, {
      data: { slug: `security-org-b-${testRunId}`, name: 'Security Test Org B' }
    });
    if (orgBResp.ok()) {
      const orgB = await orgBResp.json();
      orgBId = orgB.id;
    } else {
      throw new Error(`Failed to create org B: ${await orgBResp.text()}`);
    }

    expect(orgAId).toBeDefined();
    expect(orgBId).toBeDefined();

    // Create group A
    const groupAResp = await request.post(`${API_URL}/api/v1/admin/orgs/${orgAId}/groups`, {
      data: {
        slug: 'security-group-a',
        name: 'Security Group A'
      }
    });
    if (groupAResp.ok()) {
      const groupA = await groupAResp.json();
      groupAId = groupA.id;
    } else {
      throw new Error(`Failed to create group A: ${await groupAResp.text()}`);
    }

    // Set group A access permissions via separate endpoint
    await request.put(`${API_URL}/api/v1/admin/orgs/${orgAId}/groups/${groupAId}/access`, {
      data: {
        allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_getLogs', 'eth_getCode', 'eth_getStorageAt', 'eth_sendTransaction'],
        claims: ['deploy'] // deploy needed for unregistered contract access
      }
    });

    // Create group B
    const groupBResp = await request.post(`${API_URL}/api/v1/admin/orgs/${orgBId}/groups`, {
      data: {
        slug: 'security-group-b',
        name: 'Security Group B'
      }
    });
    if (groupBResp.ok()) {
      const groupB = await groupBResp.json();
      groupBId = groupB.id;
    } else {
      throw new Error(`Failed to create group B: ${await groupBResp.text()}`);
    }

    // Set group B access permissions via separate endpoint
    await request.put(`${API_URL}/api/v1/admin/orgs/${orgBId}/groups/${groupBId}/access`, {
      data: {
        allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber', 'eth_getLogs', 'eth_getCode', 'eth_getStorageAt', 'eth_sendTransaction'],
        claims: ['deploy'] // deploy needed for unregistered contract access
      }
    });

    // Create contracts for each org using cryptographically-random addresses
    // to avoid cross-worker collisions under parallel test execution.
    contractA = randomAddress('aa');
    contractB = randomAddress('bb');

    const contractAResp = await request.post(`${API_URL}/api/v1/admin/orgs/${orgAId}/contracts`, {
      data: { address: contractA, name: 'Contract A' }
    });
    if (!contractAResp.ok()) {
      throw new Error(`Failed to create contract A: ${await contractAResp.text()}`);
    }

    const contractBResp = await request.post(`${API_URL}/api/v1/admin/orgs/${orgBId}/contracts`, {
      data: { address: contractB, name: 'Contract B' }
    });
    if (!contractBResp.ok()) {
      throw new Error(`Failed to create contract B: ${await contractBResp.text()}`);
    }

    // Grant group A access to contract A (explicit grants required for registered contracts)
    const grantAResp = await request.post(`${API_URL}/api/v1/admin/orgs/${orgAId}/contracts/${contractA}/grants`, {
      data: { group_id: groupAId }
    });
    if (!grantAResp.ok()) {
      throw new Error(`Failed to create grant for contract A: ${await grantAResp.text()}`);
    }

    // Grant group B access to contract B
    const grantBResp = await request.post(`${API_URL}/api/v1/admin/orgs/${orgBId}/contracts/${contractB}/grants`, {
      data: { group_id: groupBId }
    });
    if (!grantBResp.ok()) {
      throw new Error(`Failed to create grant for contract B: ${await grantBResp.text()}`);
    }

    // Create unique DIDs for this test run
    const timestamp = Date.now();
    const userADID = `did:security:user-a-${timestamp}`;
    const userBDID = `did:security:user-b-${timestamp}`;

    // Step 1: Authenticate users first - this creates them via EnsureUserExists
    userAToken = await getJWTToken(request, userADID);
    userBToken = await getJWTToken(request, userBDID);

    // Step 2: Find users by external ID to get their internal IDs
    const usersResp = await request.get(`${API_URL}/api/v1/admin/users`);
    const usersData = await usersResp.json();
    const users = usersData.data;
    const userA = users.find((u: any) => u.external_id === userADID);
    const userB = users.find((u: any) => u.external_id === userBDID);

    if (!userA) {
      throw new Error(`User A not created after auth: ${userADID}`);
    }
    if (!userB) {
      throw new Error(`User B not created after auth: ${userBDID}`);
    }

    // Step 3: Update KYC status using internal IDs
    await request.put(`${API_URL}/api/v1/admin/users/${userA.id}`, {
      data: { kyc: true }
    });
    await request.put(`${API_URL}/api/v1/admin/users/${userB.id}`, {
      data: { kyc: true }
    });

    // Step 4: Add users to their respective groups using internal IDs
    if (groupAId) {
      const memAResp = await request.post(`${API_URL}/api/v1/admin/users/${userA.id}/memberships`, {
        data: { org_id: orgAId, group_id: groupAId }
      });
      if (!memAResp.ok()) {
        throw new Error(`Failed to create membership for user A: ${await memAResp.text()}`);
      }
    }
    if (groupBId) {
      const memBResp = await request.post(`${API_URL}/api/v1/admin/users/${userB.id}/memberships`, {
        data: { org_id: orgBId, group_id: groupBId }
      });
      if (!memBResp.ok()) {
        throw new Error(`Failed to create membership for user B: ${await memBResp.text()}`);
      }
    }

    // Step 5: Get new JWT tokens with updated KYC status
    userAToken = await getJWTToken(request, userADID);
    userBToken = await getJWTToken(request, userBDID);

    // Warm RBAC/cache state so early test requests don't fail with transient 403s.
    const userAAccess = await waitForContractAccess(request, userAToken, contractA);
    expect(userAAccess.status, `User A setup did not propagate for ${contractA}`).not.toBe(403);

    const userBAccess = await waitForContractAccess(request, userBToken, contractB);
    expect(userBAccess.status, `User B setup did not propagate for ${contractB}`).not.toBe(403);
  });

  test('SECURITY-001: User A cannot access Contract B (cross-org isolation)', async ({ request }) => {
    // User A tries to read Contract B (belongs to Org B)
    const result = await rpcCall(request, userAToken, 'eth_call', [
      { to: contractB, data: '0x' },
      'latest'
    ]);

    // Should be denied due to cross-org isolation
    expect(result.status).toBe(404); // opaque RBAC denial
    expect(result.body.error).toContain('method not found');
  });

  test('SECURITY-002: User B cannot access Contract A (cross-org isolation)', async ({ request }) => {
    // User B tries to read Contract A (belongs to Org A)
    const result = await rpcCall(request, userBToken, 'eth_call', [
      { to: contractA, data: '0x' },
      'latest'
    ]);

    // Should be denied due to cross-org isolation
    expect(result.status).toBe(404); // opaque RBAC denial
    expect(result.body.error).toContain('method not found');
  });

  test('SECURITY-003: User A CAN access their own Contract A', async ({ request }) => {
    // User A reads Contract A (their own org).
    // Retry briefly to avoid false negatives from short-lived cache propagation delay.
    const result = await waitForContractAccess(request, userAToken, contractA);

    // May fail due to contract not existing on-chain, but should NOT be 403 forbidden
    // 502 (node error) or 200 are acceptable
    expect(result.status).not.toBe(403);
  });

  test('SECURITY-004: eth_getLogs cannot include cross-org contracts', async ({ request }) => {
    // User A tries to get logs from Contract B
    const result = await rpcCall(request, userAToken, 'eth_getLogs', [
      { address: contractB, fromBlock: '0x0', toBlock: 'latest' }
    ]);

    // Should be denied
    expect(result.status).toBe(404); // opaque RBAC denial
    expect(result.body.error).toContain('method not found');
  });

  test('SECURITY-005: eth_getLogs with mixed-org addresses is denied', async ({ request }) => {
    // User A tries to get logs from both Contract A AND Contract B
    const result = await rpcCall(request, userAToken, 'eth_getLogs', [
      { address: [contractA, contractB], fromBlock: '0x0', toBlock: 'latest' }
    ]);

    // Should be denied because contractB is from another org
    expect(result.status).toBe(404); // opaque RBAC denial
  });

  test('SECURITY-006: eth_getBalance on cross-org address is denied (private-by-default)', async ({ request }) => {
    // Per RD-855 (commit 1ba8da5), all addresses go through contract-level
    // checks; cross-org contracts are denied even for account queries.
    const result = await rpcCall(request, userAToken, 'eth_getBalance', [
      contractB,
      'latest'
    ]);

    expect(result.status).toBe(404);
  });

  test('SECURITY-007: Public contract (not registered to any org) is accessible', async ({ request }) => {
    // Create an address that's not registered to any org.
    const publicContract = randomAddress('ee');

    // User A should be able to access via claims
    const result = await rpcCall(request, userAToken, 'eth_call', [
      { to: publicContract, data: '0x' },
      'latest'
    ]);

    // Should NOT be 403 - might be 502 if contract doesn't exist on-chain
    expect(result.status).not.toBe(403);
  });

  test('SECURITY-008: eth_getCode on cross-org contract is denied', async ({ request }) => {
    const result = await rpcCall(request, userAToken, 'eth_getCode', [
      contractB,
      'latest'
    ]);

    expect(result.status).toBe(404); // opaque RBAC denial
  });

  test('SECURITY-009: eth_getStorageAt on cross-org contract is denied', async ({ request }) => {
    const result = await rpcCall(request, userAToken, 'eth_getStorageAt', [
      contractB,
      '0x0',
      'latest'
    ]);

    expect(result.status).toBe(404); // opaque RBAC denial
  });

  test('SECURITY-010: eth_sendTransaction to cross-org contract is denied', async ({ request }) => {
    const result = await rpcCall(request, userAToken, 'eth_sendTransaction', [
      { to: contractB, from: '0x' + '9'.repeat(40), data: '0x' }
    ]);

    // Should be denied - either 403 (RBAC) or might also fail for other reasons
    // but definitely should not succeed
    expect(result.status).not.toBe(200);
  });
});
