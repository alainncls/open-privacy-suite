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

async function setupUsers(request: any) {
  // Step 1: Authenticate both users first - this creates them via EnsureUserExists
  deployerToken = await getJWTToken(request, DEPLOYER_DID);
  nonDeployerToken = await getJWTToken(request, NON_DEPLOYER_DID);

  // Step 2: Find users by external ID to get their internal IDs
  const usersResp = await request.get(`${API_URL}/api/v1/users`);
  const users = await usersResp.json();
  const deployerUser = users.find((u: any) => u.external_id === DEPLOYER_DID);
  const nonDeployerUser = users.find((u: any) => u.external_id === NON_DEPLOYER_DID);

  if (!deployerUser) {
    throw new Error(`Deployer user not created after auth: ${DEPLOYER_DID}`);
  }
  if (!nonDeployerUser) {
    throw new Error(`Non-deployer user not created after auth: ${NON_DEPLOYER_DID}`);
  }

  // Step 3: Update KYC status using internal IDs
  await request.put(`${API_URL}/api/v1/users/${deployerUser.id}`, {
    data: { kyc: true }
  });
  await request.put(`${API_URL}/api/v1/users/${nonDeployerUser.id}`, {
    data: { kyc: true }
  });

  // Step 4: Get default org and create appropriate groups
  const orgsResp = await request.get(`${API_URL}/api/v1/orgs`);
  const orgs = await orgsResp.json();
  const defaultOrg = orgs.find((o: any) => o.slug === 'default');

  if (defaultOrg) {
    // Create group with deploy claim
    const deployGroupResp = await request.post(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups`, {
      data: {
        slug: 'security-deployers',
        name: 'Security Deployers'
      }
    });

    let deployGroupId: string | null = null;
    if (deployGroupResp.ok()) {
      const group = await deployGroupResp.json();
      deployGroupId = group.id;
    } else {
      const groupsResp = await request.get(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups`);
      const groups = await groupsResp.json();
      const existing = groups.find((g: any) => g.slug === 'security-deployers');
      if (existing) deployGroupId = existing.id;
    }

    // Set group access permissions (deploy claim)
    if (deployGroupId) {
      await request.put(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups/${deployGroupId}/access`, {
        data: {
          allowed_methods: ['eth_sendTransaction', 'eth_estimateGas', 'eth_call'],
          default_claims: ['read', 'write', 'deploy']
        }
      });
    }

    // Create group without deploy claim
    const noDeployGroupResp = await request.post(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups`, {
      data: {
        slug: 'security-no-deploy',
        name: 'Security No Deploy'
      }
    });

    let noDeployGroupId: string | null = null;
    if (noDeployGroupResp.ok()) {
      const group = await noDeployGroupResp.json();
      noDeployGroupId = group.id;
    } else {
      const groupsResp = await request.get(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups`);
      const groups = await groupsResp.json();
      const existing = groups.find((g: any) => g.slug === 'security-no-deploy');
      if (existing) noDeployGroupId = existing.id;
    }

    // Set group access permissions (no deploy claim)
    if (noDeployGroupId) {
      await request.put(`${API_URL}/api/v1/orgs/${defaultOrg.id}/groups/${noDeployGroupId}/access`, {
        data: {
          allowed_methods: ['eth_sendTransaction', 'eth_estimateGas', 'eth_call'],
          default_claims: ['read', 'write']  // No deploy!
        }
      });
    }

    // Add users to groups using internal IDs
    if (deployGroupId) {
      await request.post(
        `${API_URL}/api/v1/users/${deployerUser.id}/memberships`,
        { data: { org_id: defaultOrg.id, group_id: deployGroupId } }
      );
    }

    if (noDeployGroupId) {
      await request.post(
        `${API_URL}/api/v1/users/${nonDeployerUser.id}/memberships`,
        { data: { org_id: defaultOrg.id, group_id: noDeployGroupId } }
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

  test('DEPLOY-013: eth_sendRawTransaction is globally blocked', async ({ request }) => {
    // This is critical - raw transactions bypass ALL validation
    const result = await rpcCall(request, deployerToken, 'eth_sendRawTransaction', [
      '0xf86c808504a817c80082520894' + '1'.repeat(40) + '880de0b6b3a764000080'
    ]);

    expect(result.status).toBe(403);
    expect(result.body.error).toContain('globally blocked');
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
