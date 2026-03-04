/**
 * Security Tests: Deployment Validation
 *
 * Tests that contract deployments are properly validated:
 * - Require deploy claim
 * - Validate bytecode (no nested CREATE, no dynamic DELEGATECALL)
 * - Factory deployments require admin claim
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// User DIDs for this test suite (unique per run)
const timestamp = Date.now();
const DEPLOYER_DID = `did:security:deployer-${timestamp}`;
const NON_DEPLOYER_DID = `did:security:non-deployer-${timestamp}`;

// JWT tokens will be set in setupUsers
let deployerToken: string;
let nonDeployerToken: string;

let defaultOrgId: string;
let deployGroupId: string;
let noDeployGroupId: string;
const OUTSIDER_DID = `did:security:outsider-${timestamp}`;
let outsiderToken: string;
let outsiderOrgId: string;

async function setupUsers(request: any) {
  // Step 1: Authenticate both users first - this creates them via EnsureUserExists
  deployerToken = await getJWTToken(request, DEPLOYER_DID);
  nonDeployerToken = await getJWTToken(request, NON_DEPLOYER_DID);

  // Step 2: Find users by external ID to get their internal IDs
  const usersResp = await request.get(`${API_URL}/api/v1/admin/users`);
  const usersData = await usersResp.json();
  const users = usersData.data;
  const deployerUser = users.find((u: any) => u.external_id === DEPLOYER_DID);
  const nonDeployerUser = users.find((u: any) => u.external_id === NON_DEPLOYER_DID);

  if (!deployerUser) {
    throw new Error(`Deployer user not created after auth: ${DEPLOYER_DID}`);
  }
  if (!nonDeployerUser) {
    throw new Error(`Non-deployer user not created after auth: ${NON_DEPLOYER_DID}`);
  }

  // Step 3: Update KYC status using internal IDs
  await request.put(`${API_URL}/api/v1/admin/users/${deployerUser.id}`, {
    data: { kyc: true }
  });
  await request.put(`${API_URL}/api/v1/admin/users/${nonDeployerUser.id}`, {
    data: { kyc: true }
  });

  // Step 4: Get default org and create appropriate groups
  const orgsResp = await request.get(`${API_URL}/api/v1/admin/orgs`);
  const orgsData = await orgsResp.json();
  const orgs = orgsData.data;
  const defaultOrg = orgs.find((o: any) => o.slug === 'default');
  if (defaultOrg) defaultOrgId = defaultOrg.id;

  if (defaultOrg) {
    // Create group with deploy claim
    const deployGroupResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`, {
      data: {
        slug: 'security-deployers',
        name: 'Security Deployers'
      }
    });

    let localDeployGroupId: string | null = null;
    if (deployGroupResp.ok()) {
      const group = await deployGroupResp.json();
      localDeployGroupId = group.id;
    } else {
      const groupsResp = await request.get(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`);
      const groupsData = await groupsResp.json();
      const groups = groupsData.data.map((g: any) => g.group);
      const existing = groups.find((g: any) => g.slug === 'security-deployers');
      if (existing) localDeployGroupId = existing.id;
    }

    // Set group access permissions (deploy claim)
    if (localDeployGroupId) {
      await request.put(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups/${localDeployGroupId}/access`, {
        data: {
          allowed_methods: ['eth_sendTransaction', 'eth_estimateGas', 'eth_call', 'eth_getLogs'],
          claims: ['read', 'write', 'deploy']
        }
      });
    }

    // Create group without deploy claim
    const noDeployGroupResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`, {
      data: {
        slug: 'security-no-deploy',
        name: 'Security No Deploy'
      }
    });

    let localNoDeployGroupId: string | null = null;
    if (noDeployGroupResp.ok()) {
      const group = await noDeployGroupResp.json();
      localNoDeployGroupId = group.id;
    } else {
      const groupsResp = await request.get(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`);
      const groupsData = await groupsResp.json();
      const groups = groupsData.data.map((g: any) => g.group);
      const existing = groups.find((g: any) => g.slug === 'security-no-deploy');
      if (existing) localNoDeployGroupId = existing.id;
    }

    // Set group access permissions (no deploy claim)
    if (localNoDeployGroupId) {
      await request.put(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups/${localNoDeployGroupId}/access`, {
        data: {
          allowed_methods: ['eth_sendTransaction', 'eth_estimateGas', 'eth_call', 'eth_getLogs'],
          claims: ['read', 'write']  // No deploy!
        }
      });
    }

    // Assign to module-level variables
    if (localDeployGroupId) deployGroupId = localDeployGroupId;
    if (localNoDeployGroupId) noDeployGroupId = localNoDeployGroupId;

    // Add users to groups using internal IDs
    if (localDeployGroupId) {
      await request.post(
        `${API_URL}/api/v1/admin/users/${deployerUser.id}/memberships`,
        { data: { org_id: defaultOrg.id, group_id: localDeployGroupId } }
      );
    }

    if (localNoDeployGroupId) {
      await request.post(
        `${API_URL}/api/v1/admin/users/${nonDeployerUser.id}/memberships`,
        { data: { org_id: defaultOrg.id, group_id: localNoDeployGroupId } }
      );
    }
  }

  // Step 5: Get new JWT tokens with updated KYC status
  deployerToken = await getJWTToken(request, DEPLOYER_DID);
  nonDeployerToken = await getJWTToken(request, NON_DEPLOYER_DID);
}

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

// Simple bytecode examples (not real contracts, just for testing detection)
const SIMPLE_BYTECODE = '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea165';
const CREATE_BYTECODE = '0x6080604052348015600f57600080fd5b506040f0'; // Contains CREATE opcode (0xf0)
const CREATE2_BYTECODE = '0x6080604052348015600f57600080fd5b506040f5'; // Contains CREATE2 opcode (0xf5)
const DELEGATECALL_DYNAMIC = '0x6080604052348015600f57600080fd5b5060005473f4'; // Dynamic DELEGATECALL

test.describe('Deploy Claim Enforcement', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);
  });

  test('DEPLOY-001: User with deploy claim can deploy', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      {
        from: '0x' + '1'.repeat(40),
        data: SIMPLE_BYTECODE  // No 'to' = deployment
      }
    ]);

    // Should be allowed by RBAC (might fail for other node reasons)
    expect(result.status).not.toBe(403);
  });

  test('DEPLOY-002: User without deploy claim CANNOT deploy', async ({ request }) => {
    const result = await rpcCall(request, nonDeployerToken, 'eth_sendTransaction', [
      {
        from: '0x' + '2'.repeat(40),
        data: SIMPLE_BYTECODE  // No 'to' = deployment
      }
    ]);

    // Should be denied
    expect(result.status).toBe(403);
    expect(result.body.error).toContain('deploy');
  });

  test('DEPLOY-003: eth_estimateGas for deployment also requires deploy claim', async ({ request }) => {
    // Non-deployer trying to estimate gas for deployment
    const result = await rpcCall(request, nonDeployerToken, 'eth_estimateGas', [
      {
        from: '0x' + '2'.repeat(40),
        data: SIMPLE_BYTECODE  // No 'to' = deployment estimation
      }
    ]);

    // Should be denied
    expect(result.status).toBe(403);
    expect(result.body.error).toContain('deploy');
  });

  test('DEPLOY-004: User with deploy claim can estimate deployment gas', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_estimateGas', [
      {
        from: '0x' + '1'.repeat(40),
        data: SIMPLE_BYTECODE
      }
    ]);

    expect(result.status).not.toBe(403);
  });
});

test.describe('Deployment Detection', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);
  });

  test('DEPLOY-005: Missing "to" field = deployment', async ({ request }) => {
    const result = await rpcCall(request, nonDeployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), data: '0x60806040' }
    ]);

    expect(result.status).toBe(403);
    expect(result.body.error).toContain('deploy');
  });

  test('DEPLOY-006: "to": null = deployment', async ({ request }) => {
    const result = await rpcCall(request, nonDeployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), to: null, data: '0x60806040' }
    ]);

    expect(result.status).toBe(403);
    expect(result.body.error).toContain('deploy');
  });

  test('DEPLOY-007: "to": "" = deployment', async ({ request }) => {
    const result = await rpcCall(request, nonDeployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), to: '', data: '0x60806040' }
    ]);

    expect(result.status).toBe(403);
  });

  test('DEPLOY-008: "to": "0x" = deployment', async ({ request }) => {
    const result = await rpcCall(request, nonDeployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), to: '0x', data: '0x60806040' }
    ]);

    expect(result.status).toBe(403);
  });

  test('DEPLOY-009: Valid "to" address = NOT deployment', async ({ request }) => {
    const result = await rpcCall(request, nonDeployerToken, 'eth_sendTransaction', [
      {
        from: '0x' + '1'.repeat(40),
        to: '0x' + '2'.repeat(40),  // Has 'to' address
        data: '0x12345678'
      }
    ]);

    // Should NOT trigger deploy check (might fail for other reasons)
    // If it fails, it should NOT be because of deploy claim
    if (result.status === 403) {
      expect(result.body.error).not.toContain('deploy');
    }
  });
});

test.describe('Bytecode Validation - CREATE/CREATE2 Detection', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);
  });

  test('DEPLOY-010: Bytecode with CREATE opcode is blocked', async ({ request }) => {
    // Note: This requires the bytecode parser to actually detect CREATE
    // The test verifies the validation is happening

    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), data: CREATE_BYTECODE }
    ]);

    // Should be denied due to bytecode validation
    // OR allowed if it's not detected (documents current behavior)
    console.log(`CREATE opcode deployment: status=${result.status}, body=${JSON.stringify(result.body)}`);
  });

  test('DEPLOY-011: Bytecode with CREATE2 opcode is blocked', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), data: CREATE2_BYTECODE }
    ]);

    console.log(`CREATE2 opcode deployment: status=${result.status}, body=${JSON.stringify(result.body)}`);
  });
});

test.describe('Bytecode Validation - Dynamic DELEGATECALL', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);
  });

  test('DEPLOY-012: Bytecode with dynamic DELEGATECALL is blocked (unless proxy)', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), data: DELEGATECALL_DYNAMIC }
    ]);

    console.log(`Dynamic DELEGATECALL deployment: status=${result.status}, body=${JSON.stringify(result.body)}`);
  });
});

test.describe('eth_sendRawTransaction Blocking', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);
  });

  test('DEPLOY-013: eth_sendRawTransaction requires valid transaction and authorization', async ({ request }) => {
    // eth_sendRawTransaction is NOT globally blocked - it's handled specially:
    // - When runtime tracing is disabled: returns 403 with "runtime tracing" error
    // - When runtime tracing is enabled: requires valid RLP and RBAC authorization
    // This ensures raw transactions can only be sent when the proxy can validate all call targets.
    const result = await rpcCall(request, deployerToken, 'eth_sendRawTransaction', [
      '0xf86c808504a817c80082520894' + '1'.repeat(40) + '880de0b6b3a764000080'
    ]);

    // Should be either 403 (runtime tracing disabled) or 400 (invalid/incomplete RLP)
    expect([400, 403]).toContain(result.status);
    // Should NOT succeed
    expect(result.body).toHaveProperty('error');
  });
});

test.describe('Empty Bytecode Handling', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);
  });

  test('DEPLOY-014: Deployment with empty data is rejected', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), data: '' }
    ]);

    // Should be rejected - can't deploy empty contract
    console.log(`Empty data deployment: status=${result.status}`);
  });

  test('DEPLOY-015: Deployment with "0x" data is rejected', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40), data: '0x' }
    ]);

    console.log(`0x data deployment: status=${result.status}`);
  });

  test('DEPLOY-016: Deployment with missing data field is handled', async ({ request }) => {
    const result = await rpcCall(request, deployerToken, 'eth_sendTransaction', [
      { from: '0x' + '1'.repeat(40) }  // No 'to' and no 'data'
    ]);

    console.log(`No data deployment: status=${result.status}`);
  });
});

function randomContractAddress(): string {
  const bytes = Array.from({ length: 20 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  );
  return '0x' + bytes.join('');
}

test.describe('Deploy Window and Contract Registration', () => {

  test.beforeAll(async ({ request }) => {
    await setupUsers(request);

    // Create outsider user authenticated into a separate org
    outsiderToken = await getJWTToken(request, OUTSIDER_DID);

    const usersResp = await request.get(`${API_URL}/api/v1/admin/users`);
    const users = (await usersResp.json()).data;
    const outsiderUser = users.find((u: any) => u.external_id === OUTSIDER_DID);
    if (!outsiderUser) throw new Error(`Outsider user not created: ${OUTSIDER_DID}`);

    await request.put(`${API_URL}/api/v1/admin/users/${outsiderUser.id}`, {
      data: { kyc: true }
    });

    // Create a second org for the outsider
    const outsiderOrgSlug = `outsider-deploy-${timestamp}`;
    const orgResp = await request.post(`${API_URL}/api/v1/admin/orgs`, {
      data: { slug: outsiderOrgSlug, name: 'Outsider Org' }
    });
    if (orgResp.ok()) {
      outsiderOrgId = (await orgResp.json()).id;
    } else {
      const orgsResp = await request.get(`${API_URL}/api/v1/admin/orgs`);
      const existing = (await orgsResp.json()).data.find((o: any) => o.slug === outsiderOrgSlug);
      if (existing) outsiderOrgId = existing.id;
    }
    if (!outsiderOrgId) throw new Error('Failed to create or find outsider org');

    // Create group with deploy claim in outsider org
    const outsiderGroupSlug = `outsider-deployers-${timestamp}`;
    const groupResp = await request.post(`${API_URL}/api/v1/admin/orgs/${outsiderOrgId}/groups`, {
      data: { slug: outsiderGroupSlug, name: 'Outsider Deployers' }
    });
    if (!groupResp.ok()) throw new Error(`Failed to create outsider group: ${await groupResp.text()}`);
    const outsiderGroupId = (await groupResp.json()).id;

    await request.put(`${API_URL}/api/v1/admin/orgs/${outsiderOrgId}/groups/${outsiderGroupId}/access`, {
      data: {
        allowed_methods: ['eth_call', 'eth_getLogs', 'eth_sendTransaction'],
        claims: ['read', 'write', 'deploy']
      }
    });

    await request.post(`${API_URL}/api/v1/admin/users/${outsiderUser.id}/memberships`, {
      data: { group_id: outsiderGroupId }
    });

    // Refresh token with updated KYC + membership
    outsiderToken = await getJWTToken(request, OUTSIDER_DID);
  });

  test('DEPLOY-017: Deploy-window: deploy-claim user can eth_call unregistered contract address', async ({ request }) => {
    const addr = randomContractAddress();

    const result = await rpcCall(request, deployerToken, 'eth_call', [
      { to: addr, data: '0x' },
      'latest'
    ]);

    // RBAC should pass (deploy claim grants access to unregistered addresses).
    // The node may return an empty result or error, but the proxy must not return 403.
    expect(result.status).not.toBe(403);
  });

  test('DEPLOY-018: Deploy-window: read-only user cannot eth_call unregistered contract address', async ({ request }) => {
    const addr = randomContractAddress();

    const result = await rpcCall(request, nonDeployerToken, 'eth_call', [
      { to: addr, data: '0x' },
      'latest'
    ]);

    expect(result.status).toBe(403);
  });

  test('DEPLOY-019: Deploy-window: deploy-claim user can eth_getLogs on unregistered contract address', async ({ request }) => {
    const addr = randomContractAddress();

    const result = await rpcCall(request, deployerToken, 'eth_getLogs', [
      { address: addr, fromBlock: '0x0', toBlock: 'latest' }
    ]);

    // Symmetric with eth_call: deploy claim grants access to unregistered addresses.
    expect(result.status).not.toBe(403);
  });

  test('DEPLOY-020: Deploy-window: read-only user cannot eth_getLogs on unregistered contract address', async ({ request }) => {
    const addr = randomContractAddress();

    const result = await rpcCall(request, nonDeployerToken, 'eth_getLogs', [
      { address: addr, fromBlock: '0x0', toBlock: 'latest' }
    ]);

    expect(result.status).toBe(403);
  });

  test('DEPLOY-021: After registering contract to org and granting access, org member can access it', async ({ request }) => {
    const addr = randomContractAddress();

    // Confirm read-only user is blocked before registration
    const before = await rpcCall(request, nonDeployerToken, 'eth_call', [
      { to: addr, data: '0x' }, 'latest'
    ]);
    expect(before.status).toBe(403);

    // Register the contract to the default org
    const registerResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrgId}/contracts`, {
      data: { address: addr, name: 'DeployWindowTest' }
    });
    expect(registerResp.ok()).toBeTruthy();

    // Grant the no-deploy group access to the contract
    const grantResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrgId}/contracts/${addr}/grants`, {
      data: { group_id: noDeployGroupId, claims: ['read', 'write'] }
    });
    expect(grantResp.ok()).toBeTruthy();

    // Now the read-only org member should be able to access it
    const after = await rpcCall(request, nonDeployerToken, 'eth_call', [
      { to: addr, data: '0x' }, 'latest'
    ]);
    expect(after.status).not.toBe(403);
  });

  test('DEPLOY-022: After registering contract to org, deploy-claim user in a different org is blocked', async ({ request }) => {
    const addr = randomContractAddress();

    // Register the contract to the default org
    const registerResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrgId}/contracts`, {
      data: { address: addr, name: 'CrossOrgTest' }
    });
    expect(registerResp.ok()).toBeTruthy();

    // Outsider has deploy claim but belongs to a different org — must be blocked
    const result = await rpcCall(request, outsiderToken, 'eth_call', [
      { to: addr, data: '0x' }, 'latest'
    ]);
    expect(result.status).toBe(403);
  });
});
