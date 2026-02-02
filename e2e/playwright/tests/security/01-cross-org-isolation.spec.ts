/**
 * Security Tests: Cross-Organization Isolation
 *
 * These tests verify that users in one organization cannot access
 * contracts or data belonging to another organization.
 *
 * CRITICAL: Cross-org leakage is a P0 security issue.
 */

import { test, expect } from '@playwright/test';

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// Helper to create a user and get a mock token
async function createUserWithToken(request: any, userDID: string, orgSlug: string = 'default') {
  // First ensure user exists in RBAC
  const orgsResp = await request.get(`${API_URL}/api/v1/orgs`);
  const orgs = await orgsResp.json();
  const org = orgs.find((o: any) => o.slug === orgSlug);

  if (!org) {
    throw new Error(`Organization ${orgSlug} not found`);
  }

  // Create or get user
  const usersResp = await request.get(`${API_URL}/api/v1/orgs/${org.id}/users`);
  const users = await usersResp.json();
  let user = users.find((u: any) => u.external_id === userDID);

  if (!user) {
    // User doesn't exist - we need to create via auth flow or admin API
    const createResp = await request.post(`${API_URL}/api/v1/orgs/${org.id}/users`, {
      data: { external_id: userDID, kyc: true }
    });
    if (createResp.ok()) {
      user = await createResp.json();
    }
  }

  // For testing, we use mock JWT token
  // In dev mode, the proxy accepts mock.DID tokens
  return `mock.${userDID}`;
}

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

test.describe('Cross-Organization Isolation', () => {
  let orgAId: string;
  let orgBId: string;
  let contractA: string;
  let contractB: string;
  let userAToken: string;
  let userBToken: string;
  let groupAId: string;
  let groupBId: string;

  test.beforeAll(async ({ request }) => {
    // Create Organization A
    const orgAResp = await request.post(`${API_URL}/api/v1/orgs`, {
      data: { slug: 'security-org-a', name: 'Security Test Org A' }
    });
    if (orgAResp.ok()) {
      const orgA = await orgAResp.json();
      orgAId = orgA.id;
    } else {
      // Org might exist, try to get it
      const orgsResp = await request.get(`${API_URL}/api/v1/orgs`);
      const orgs = await orgsResp.json();
      const existingOrgA = orgs.find((o: any) => o.slug === 'security-org-a');
      if (existingOrgA) {
        orgAId = existingOrgA.id;
      }
    }

    // Create Organization B
    const orgBResp = await request.post(`${API_URL}/api/v1/orgs`, {
      data: { slug: 'security-org-b', name: 'Security Test Org B' }
    });
    if (orgBResp.ok()) {
      const orgB = await orgBResp.json();
      orgBId = orgB.id;
    } else {
      const orgsResp = await request.get(`${API_URL}/api/v1/orgs`);
      const orgs = await orgsResp.json();
      const existingOrgB = orgs.find((o: any) => o.slug === 'security-org-b');
      if (existingOrgB) {
        orgBId = existingOrgB.id;
      }
    }

    expect(orgAId).toBeDefined();
    expect(orgBId).toBeDefined();

    // Create groups with read permissions
    const groupAResp = await request.post(`${API_URL}/api/v1/orgs/${orgAId}/groups`, {
      data: {
        slug: 'security-group-a',
        name: 'Security Group A',
        allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
        default_claims: ['read']
      }
    });
    if (groupAResp.ok()) {
      const groupA = await groupAResp.json();
      groupAId = groupA.id;
    } else {
      const groupsResp = await request.get(`${API_URL}/api/v1/orgs/${orgAId}/groups`);
      const groups = await groupsResp.json();
      const existingGroup = groups.find((g: any) => g.slug === 'security-group-a');
      if (existingGroup) {
        groupAId = existingGroup.id;
      }
    }

    const groupBResp = await request.post(`${API_URL}/api/v1/orgs/${orgBId}/groups`, {
      data: {
        slug: 'security-group-b',
        name: 'Security Group B',
        allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
        default_claims: ['read']
      }
    });
    if (groupBResp.ok()) {
      const groupB = await groupBResp.json();
      groupBId = groupB.id;
    } else {
      const groupsResp = await request.get(`${API_URL}/api/v1/orgs/${orgBId}/groups`);
      const groups = await groupsResp.json();
      const existingGroup = groups.find((g: any) => g.slug === 'security-group-b');
      if (existingGroup) {
        groupBId = existingGroup.id;
      }
    }

    // Create contracts for each org (using fake addresses for testing)
    contractA = '0x' + 'a'.repeat(40); // 0xaaaa...
    contractB = '0x' + 'b'.repeat(40); // 0xbbbb...

    await request.post(`${API_URL}/api/v1/orgs/${orgAId}/contracts`, {
      data: { address: contractA, name: 'Contract A' }
    });
    await request.post(`${API_URL}/api/v1/orgs/${orgBId}/contracts`, {
      data: { address: contractB, name: 'Contract B' }
    });

    // Create users with tokens
    userAToken = `mock.did:security:user-a-${Date.now()}`;
    userBToken = `mock.did:security:user-b-${Date.now()}`;

    // Create users in their respective orgs
    const userADID = userAToken.replace('mock.', '');
    const userBDID = userBToken.replace('mock.', '');

    // Create user A and add to group A
    await request.put(`${API_URL}/api/v1/users/${encodeURIComponent(userADID)}`, {
      data: { kyc: true }
    });
    if (groupAId) {
      await request.post(`${API_URL}/api/v1/orgs/${orgAId}/users/${encodeURIComponent(userADID)}/memberships`, {
        data: { group_id: groupAId }
      });
    }

    // Create user B and add to group B
    await request.put(`${API_URL}/api/v1/users/${encodeURIComponent(userBDID)}`, {
      data: { kyc: true }
    });
    if (groupBId) {
      await request.post(`${API_URL}/api/v1/orgs/${orgBId}/users/${encodeURIComponent(userBDID)}/memberships`, {
        data: { group_id: groupBId }
      });
    }
  });

  test('SECURITY-001: User A cannot access Contract B (cross-org isolation)', async ({ request }) => {
    // User A tries to read Contract B (belongs to Org B)
    const result = await rpcCall(request, userAToken, 'eth_call', [
      { to: contractB, data: '0x' },
      'latest'
    ]);

    // Should be denied due to cross-org isolation
    expect(result.status).toBe(403);
    expect(result.body.error).toContain('registered to another organization');
  });

  test('SECURITY-002: User B cannot access Contract A (cross-org isolation)', async ({ request }) => {
    // User B tries to read Contract A (belongs to Org A)
    const result = await rpcCall(request, userBToken, 'eth_call', [
      { to: contractA, data: '0x' },
      'latest'
    ]);

    // Should be denied due to cross-org isolation
    expect(result.status).toBe(403);
    expect(result.body.error).toContain('registered to another organization');
  });

  test('SECURITY-003: User A CAN access their own Contract A', async ({ request }) => {
    // User A reads Contract A (their own org)
    const result = await rpcCall(request, userAToken, 'eth_call', [
      { to: contractA, data: '0x' },
      'latest'
    ]);

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
    expect(result.status).toBe(403);
    expect(result.body.error).toContain('registered to another organization');
  });

  test('SECURITY-005: eth_getLogs with mixed-org addresses is denied', async ({ request }) => {
    // User A tries to get logs from both Contract A AND Contract B
    const result = await rpcCall(request, userAToken, 'eth_getLogs', [
      { address: [contractA, contractB], fromBlock: '0x0', toBlock: 'latest' }
    ]);

    // Should be denied because contractB is from another org
    expect(result.status).toBe(403);
  });

  test('SECURITY-006: eth_getBalance on cross-org address uses default_claims correctly', async ({ request }) => {
    // eth_getBalance doesn't have contract-level permissions, but cross-org should still apply
    // This tests whether default_claims can be abused for cross-org access
    const result = await rpcCall(request, userAToken, 'eth_getBalance', [
      contractB,
      'latest'
    ]);

    // If cross-org isolation is working, this should be denied
    // OR allowed only for truly public addresses (not registered to any org)
    // Since contractB IS registered to orgB, it should be denied
    expect(result.status).toBe(403);
  });

  test('SECURITY-007: Public contract (not registered to any org) is accessible', async ({ request }) => {
    // Create an address that's not registered to any org
    const publicContract = '0x' + '1'.repeat(40);

    // User A should be able to access via default_claims
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

    expect(result.status).toBe(403);
  });

  test('SECURITY-009: eth_getStorageAt on cross-org contract is denied', async ({ request }) => {
    const result = await rpcCall(request, userAToken, 'eth_getStorageAt', [
      contractB,
      '0x0',
      'latest'
    ]);

    expect(result.status).toBe(403);
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
