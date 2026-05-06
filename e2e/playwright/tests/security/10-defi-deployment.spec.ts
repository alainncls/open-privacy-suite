/**
 * E2E Tests: DeFi Contract Deployment Flow
 *
 * These tests verify the complete deployment workflow for
 * DeFi contracts (Token + Pool + Router) through the privacy proxy:
 * - Address preregistration via API
 * - CREATE3 deterministic deployment
 * - Contract interaction (swaps)
 * - Upgrade flow (V1 to V2)
 * - Cross-org isolation maintained
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';

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

// Helper to make admin API call
async function apiCall(request: any, method: string, path: string, data?: any) {
  const options: any = {
    headers: { 'Content-Type': 'application/json' }
  };
  if (data) {
    options.data = data;
  }

  const resp = method === 'GET'
    ? await request.get(`${API_URL}${path}`, options)
    : method === 'POST'
      ? await request.post(`${API_URL}${path}`, options)
      : method === 'PUT'
        ? await request.put(`${API_URL}${path}`, options)
        : await request.delete(`${API_URL}${path}`, options);

  return {
    status: resp.status(),
    ok: resp.ok(),
    body: await resp.json().catch(() => resp.text())
  };
}

// Generate unique salt prefix for test isolation
function generateSaltPrefix(base: string): string {
  return `0x${base}${Date.now().toString(16).slice(-8)}`;
}

// Sample bytecode (minimal EVM bytecode for testing)
const SIMPLE_BYTECODE = '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea165';

// Sample constructor ABI for a token with initial supply
const TOKEN_CONSTRUCTOR_ABI = JSON.stringify([
  {
    type: 'constructor',
    inputs: [
      { name: 'name', type: 'string' },
      { name: 'symbol', type: 'string' },
      { name: 'initialSupply', type: 'uint256' }
    ]
  }
]);

// Sample constructor ABI for a pool with token addresses
const POOL_CONSTRUCTOR_ABI = JSON.stringify([
  {
    type: 'constructor',
    inputs: [
      { name: 'token0', type: 'address' },
      { name: 'token1', type: 'address' },
      { name: 'fee', type: 'uint24' }
    ]
  }
]);

// Sample constructor ABI for a router
const ROUTER_CONSTRUCTOR_ABI = JSON.stringify([
  {
    type: 'constructor',
    inputs: [
      { name: 'factory', type: 'address' },
      { name: 'weth', type: 'address' }
    ]
  }
]);

// OBSOLETE: this entire flow exercises the CREATE3 factory infrastructure
// (admin /addresses/preregister and /config/create3 endpoints), which was
// removed in commit f926200 ("redundant with runtime tracing"). The remaining
// runtime-tracing path is covered by 09-runtime-tracing.spec.ts and the Go
// integration tests in e2e/create2_test.go. Skipping rather than rewriting
// because the equivalent Go tests already cover the post-CREATE3 design.
test.describe.skip('DeFi Contract Deployment Flow', () => {
  let orgId: string;
  let orgSlug: string;
  let groupId: string;
  let userToken: string;
  let testRunId: string;
  let factoryAddress: string;

  // Preregistered addresses for the DeFi stack
  let tokenAddress: string;
  let poolAddress: string;
  let routerAddress: string;

  test.beforeAll(async ({ request }) => {
    // Generate unique test run ID (must be before early return so nested beforeAll can use it)
    testRunId = `${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    orgSlug = `defi-test-${testRunId}`;

    // Create Organization for DeFi deployment
    const orgResp = await apiCall(request, 'POST', '/api/v1/admin/orgs', {
      slug: orgSlug,
      name: 'DeFi Deployment Test Org'
    });
    if (!orgResp.ok) {
      throw new Error(`Failed to create org: ${JSON.stringify(orgResp.body)}`);
    }
    orgId = orgResp.body.id;

    // Create group with deploy permissions
    const groupResp = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/groups`, {
      slug: 'defi-deployers',
      name: 'DeFi Deployers'
    });
    if (!groupResp.ok) {
      throw new Error(`Failed to create group: ${JSON.stringify(groupResp.body)}`);
    }
    groupId = groupResp.body.id;

    // Set group access with deploy claim
    await apiCall(request, 'PUT', `/api/v1/admin/orgs/${orgId}/groups/${groupId}/access`, {
      allowed_methods: [
        'eth_call',
        'eth_sendTransaction',
        'eth_estimateGas',
        'eth_getBalance',
        'eth_getCode',
        'eth_getTransactionReceipt'
      ],
      claims: ['read', 'write', 'deploy']
    });

    // Create and setup user
    const userDID = `did:defi:deployer-${testRunId}`;
    userToken = await getJWTToken(request, userDID);

    // Find user and update KYC + membership
    const usersResp = await apiCall(request, 'GET', '/api/v1/admin/users');
    const users = usersResp.body.data;
    const user = users.find((u: any) => u.external_id === userDID);
    if (!user) {
      throw new Error(`User not created after auth: ${userDID}`);
    }

    await apiCall(request, 'PUT', `/api/v1/admin/users/${user.id}`, { kyc: true });
    await apiCall(request, 'POST', `/api/v1/admin/users/${user.id}/memberships`, {
      org_id: orgId,
      group_id: groupId
    });

    // Refresh token
    userToken = await getJWTToken(request, userDID);

    // Set up a mock CREATE3 factory address
    factoryAddress = '0x' + 'ff'.repeat(20);

    // Configure factory for the org
    await apiCall(request, 'PUT', `/api/v1/admin/orgs/${orgId}/config/create3`, {
      factory: factoryAddress
    });
  });

  test.describe('Address Preregistration', () => {
    test('DEFI-001: Preregister Token address via API', async ({ request }) => {
      const saltPrefix = generateSaltPrefix('token');

      const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'DeFi Token Contract',
        constructor_abi: TOKEN_CONSTRUCTOR_ABI
      });

      expect(result.ok).toBe(true);
      expect(result.body.addresses).toBeDefined();
      expect(result.body.addresses.length).toBe(1);

      tokenAddress = result.body.addresses[0].address;
      expect(tokenAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);

      console.log(`Preregistered Token address: ${tokenAddress}`);
    });

    test('DEFI-002: Preregister Pool address via API', async ({ request }) => {
      const saltPrefix = generateSaltPrefix('pool');

      const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'DeFi Pool Contract',
        constructor_abi: POOL_CONSTRUCTOR_ABI
      });

      expect(result.ok).toBe(true);
      expect(result.body.addresses).toBeDefined();
      expect(result.body.addresses.length).toBe(1);

      poolAddress = result.body.addresses[0].address;
      expect(poolAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);

      console.log(`Preregistered Pool address: ${poolAddress}`);
    });

    test('DEFI-003: Preregister Router address via API', async ({ request }) => {
      const saltPrefix = generateSaltPrefix('router');

      const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'DeFi Router Contract',
        constructor_abi: ROUTER_CONSTRUCTOR_ABI
      });

      expect(result.ok).toBe(true);
      expect(result.body.addresses).toBeDefined();
      expect(result.body.addresses.length).toBe(1);

      routerAddress = result.body.addresses[0].address;
      expect(routerAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);

      console.log(`Preregistered Router address: ${routerAddress}`);
    });

    test('DEFI-004: Preregister multiple addresses in batch', async ({ request }) => {
      const saltPrefix = generateSaltPrefix('batch');

      const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 5,
        note: 'Batch preregistration test'
      });

      expect(result.ok).toBe(true);
      expect(result.body.addresses).toBeDefined();
      expect(result.body.addresses.length).toBe(5);

      // Each address should be unique
      const addresses = result.body.addresses.map((a: any) => a.address);
      const uniqueAddresses = new Set(addresses);
      expect(uniqueAddresses.size).toBe(5);
    });

    test('DEFI-005: List preregistered addresses', async ({ request }) => {
      const result = await apiCall(request, 'GET', `/api/v1/admin/orgs/${orgId}/addresses/preregistered`);

      expect(result.ok).toBe(true);
      expect(Array.isArray(result.body)).toBe(true);

      // Should have at least the addresses we created
      expect(result.body.length).toBeGreaterThanOrEqual(3);

      // Find our preregistered addresses
      const addresses = result.body.map((a: any) => a.address.toLowerCase());
      if (tokenAddress) {
        expect(addresses).toContain(tokenAddress.toLowerCase());
      }
    });

    test('DEFI-006: Update constructor ABI for preregistered address', async ({ request }) => {
      // First preregister a new address
      const saltPrefix = generateSaltPrefix('abiupdate');
      const preregResult = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'ABI update test'
      });

      expect(preregResult.ok).toBe(true);
      const address = preregResult.body.addresses[0].address;

      // Update the ABI
      const newABI = JSON.stringify([
        {
          type: 'constructor',
          inputs: [{ name: 'admin', type: 'address' }]
        }
      ]);

      const updateResult = await apiCall(
        request,
        'PUT',
        `/api/v1/admin/orgs/${orgId}/addresses/preregistered/${address}/abi`,
        { constructor_abi: newABI }
      );

      expect(updateResult.ok).toBe(true);
    });
  });

  test.describe('CREATE3 Deployment Simulation', () => {
    test('DEFI-007: Deployment to preregistered address is allowed', async ({ request }) => {
      // Skip if we don't have a preregistered address
      test.skip(!tokenAddress, 'No preregistered token address');

      // Simulate deployment transaction to preregistered address
      // In a real scenario, this would be via CREATE3 factory
      const result = await rpcCall(request, userToken, 'eth_call', [
        { to: tokenAddress, data: '0x' },
        'latest'
      ]);

      // Should NOT be 403 - address is preregistered for this org
      expect(result.status).not.toBe(403);
    });

    test('DEFI-008: Deployment to non-preregistered address is denied', async ({ request }) => {
      // This should be allowed for general reads via claims
      // but deployment would be denied
      const result = await rpcCall(request, userToken, 'eth_sendTransaction', [
        {
          from: '0x' + '1'.repeat(40),
          to: null, // Deployment
          data: SIMPLE_BYTECODE
        }
      ]);

      // Deployment validation should run
      // Exact result depends on configuration
      console.log(`Non-preregistered deployment: status=${result.status}`);
    });
  });

  test.describe('Contract Interaction', () => {
    test('DEFI-009: Can call preregistered contract', async ({ request }) => {
      test.skip(!tokenAddress, 'No preregistered token address');

      // Call the token contract (e.g., balanceOf)
      const balanceOfSelector = '0x70a08231'; // balanceOf(address)
      const paddedAddress = '0'.repeat(24) + '1'.repeat(40); // address parameter

      const result = await rpcCall(request, userToken, 'eth_call', [
        {
          to: tokenAddress,
          data: balanceOfSelector + paddedAddress
        },
        'latest'
      ]);

      // Should NOT be 403
      expect(result.status).not.toBe(403);
    });

    test('DEFI-010: Can estimate gas for contract interaction', async ({ request }) => {
      test.skip(!poolAddress, 'No preregistered pool address');

      const result = await rpcCall(request, userToken, 'eth_estimateGas', [
        {
          to: poolAddress,
          data: '0x12345678', // Mock function call
          from: '0x' + '1'.repeat(40)
        }
      ]);

      // Should NOT be 403
      expect(result.status).not.toBe(403);
    });

    test('DEFI-011: Swap simulation through router', async ({ request }) => {
      test.skip(!routerAddress, 'No preregistered router address');

      // Simulate a swap call
      // swapExactTokensForTokens selector: 0x38ed1739
      const swapSelector = '0x38ed1739';

      const result = await rpcCall(request, userToken, 'eth_call', [
        {
          to: routerAddress,
          data: swapSelector + '0'.repeat(64), // Minimal params
          from: '0x' + '1'.repeat(40)
        },
        'latest'
      ]);

      // Should NOT be 403 - router is preregistered
      expect(result.status).not.toBe(403);
    });
  });

  test.describe('Upgrade Flow (V1 to V2)', () => {
    let v2TokenAddress: string;

    test('DEFI-012: Preregister V2 upgrade addresses', async ({ request }) => {
      const saltPrefix = generateSaltPrefix('v2token');

      const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'Token V2 Upgrade',
        constructor_abi: TOKEN_CONSTRUCTOR_ABI
      });

      expect(result.ok).toBe(true);
      v2TokenAddress = result.body.addresses[0].address;

      console.log(`Preregistered V2 Token address: ${v2TokenAddress}`);
    });

    test('DEFI-013: V2 address is accessible after preregistration', async ({ request }) => {
      test.skip(!v2TokenAddress, 'No V2 token address');

      const result = await rpcCall(request, userToken, 'eth_call', [
        { to: v2TokenAddress, data: '0x' },
        'latest'
      ]);

      // Should NOT be 403
      expect(result.status).not.toBe(403);
    });

    test('DEFI-014: Old V1 and new V2 addresses both accessible', async ({ request }) => {
      test.skip(!tokenAddress || !v2TokenAddress, 'Missing addresses');

      // Both V1 and V2 should be accessible
      const v1Result = await rpcCall(request, userToken, 'eth_call', [
        { to: tokenAddress, data: '0x' },
        'latest'
      ]);

      const v2Result = await rpcCall(request, userToken, 'eth_call', [
        { to: v2TokenAddress, data: '0x' },
        'latest'
      ]);

      expect(v1Result.status).not.toBe(403);
      expect(v2Result.status).not.toBe(403);
    });
  });

  test.describe('Cross-Org Isolation Maintained', () => {
    let otherOrgId: string;
    let otherUserToken: string;

    test.beforeAll(async ({ request }) => {
      // Create another organization
      const otherOrgResp = await apiCall(request, 'POST', '/api/v1/admin/orgs', {
        slug: `defi-other-${testRunId}`,
        name: 'Other DeFi Org'
      });
      if (!otherOrgResp.ok) {
        throw new Error(`Failed to create other org: ${JSON.stringify(otherOrgResp.body)}`);
      }
      otherOrgId = otherOrgResp.body.id;

      // Create group for other org
      const otherGroupResp = await apiCall(request, 'POST', `/api/v1/admin/orgs/${otherOrgId}/groups`, {
        slug: 'other-defi-group',
        name: 'Other DeFi Group'
      });
      if (!otherGroupResp.ok) {
        throw new Error(`Failed to create other group: ${JSON.stringify(otherGroupResp.body)}`);
      }
      const otherGroupId = otherGroupResp.body.id;

      // Set group access
      await apiCall(request, 'PUT', `/api/v1/admin/orgs/${otherOrgId}/groups/${otherGroupId}/access`, {
        allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_estimateGas'],
        claims: ['read', 'write']
      });

      // Create user in other org
      const otherUserDID = `did:defi:other-user-${testRunId}`;
      otherUserToken = await getJWTToken(request, otherUserDID);

      const usersResp = await apiCall(request, 'GET', '/api/v1/admin/users');
      const users = usersResp.body.data;
      const otherUser = users.find((u: any) => u.external_id === otherUserDID);
      if (!otherUser) {
        throw new Error(`Other user not created: ${otherUserDID}`);
      }

      await apiCall(request, 'PUT', `/api/v1/admin/users/${otherUser.id}`, { kyc: true });
      await apiCall(request, 'POST', `/api/v1/admin/users/${otherUser.id}/memberships`, {
        org_id: otherOrgId,
        group_id: otherGroupId
      });

      otherUserToken = await getJWTToken(request, otherUserDID);
    });

    test('DEFI-015: Other org user CANNOT access our preregistered contracts', async ({ request }) => {
      test.skip(!tokenAddress, 'No preregistered token address');

      const result = await rpcCall(request, otherUserToken, 'eth_call', [
        { to: tokenAddress, data: '0x' },
        'latest'
      ]);

      // Should be 403 - cross-org isolation
      expect(result.status).toBe(403);
      expect(result.body.error).toContain('contract access denied');
    });

    test('DEFI-016: Other org user CANNOT call our pool contract', async ({ request }) => {
      test.skip(!poolAddress, 'No preregistered pool address');

      const result = await rpcCall(request, otherUserToken, 'eth_call', [
        { to: poolAddress, data: '0x12345678' },
        'latest'
      ]);

      expect(result.status).toBe(403);
    });

    test('DEFI-017: Other org user CANNOT interact with our router', async ({ request }) => {
      test.skip(!routerAddress, 'No preregistered router address');

      const result = await rpcCall(request, otherUserToken, 'eth_sendTransaction', [
        {
          from: '0x' + '2'.repeat(40),
          to: routerAddress,
          data: '0x38ed1739' // swap selector
        }
      ]);

      expect(result.status).toBe(403);
    });

    test('DEFI-018: Each org maintains independent preregistered addresses', async ({ request }) => {
      // Preregister an address for the other org
      const otherFactory = '0x' + 'ee'.repeat(20);
      const saltPrefix = generateSaltPrefix('othertok');

      // Configure factory for other org
      await apiCall(request, 'PUT', `/api/v1/admin/orgs/${otherOrgId}/config/create3`, {
        factory: otherFactory
      });

      const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${otherOrgId}/addresses/preregister`, {
        factory: otherFactory,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'Other org token'
      });

      expect(result.ok).toBe(true);
      const otherOrgAddress = result.body.addresses[0].address;

      // Verify original org's addresses are separate
      const ourAddresses = await apiCall(request, 'GET', `/api/v1/admin/orgs/${orgId}/addresses/preregistered`);
      const otherAddresses = await apiCall(request, 'GET', `/api/v1/admin/orgs/${otherOrgId}/addresses/preregistered`);

      const ourList = ourAddresses.body.map((a: any) => a.address.toLowerCase());
      const otherList = otherAddresses.body.map((a: any) => a.address.toLowerCase());

      // Other org's address should NOT be in our list
      expect(ourList).not.toContain(otherOrgAddress.toLowerCase());

      // Our addresses should NOT be in other org's list
      if (tokenAddress) {
        expect(otherList).not.toContain(tokenAddress.toLowerCase());
      }
    });
  });

  test.describe('Cleanup and Deletion', () => {
    test('DEFI-019: Can delete preregistered address before deployment', async ({ request }) => {
      // Preregister a new address for deletion test
      const saltPrefix = generateSaltPrefix('todelete');

      const preregResult = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'To be deleted'
      });

      expect(preregResult.ok).toBe(true);
      const addressToDelete = preregResult.body.addresses[0].address;

      // Delete the address
      const deleteResult = await apiCall(
        request,
        'DELETE',
        `/api/v1/admin/orgs/${orgId}/addresses/preregistered/${addressToDelete}`
      );

      expect(deleteResult.ok).toBe(true);

      // Verify it's gone
      const listResult = await apiCall(request, 'GET', `/api/v1/admin/orgs/${orgId}/addresses/preregistered`);
      const addresses = listResult.body.map((a: any) => a.address.toLowerCase());
      expect(addresses).not.toContain(addressToDelete.toLowerCase());
    });

    test('DEFI-020: Cannot delete deployed contract (status check)', async ({ request }) => {
      // This test documents the expected behavior
      // A deployed contract should not be deletable from preregistered list

      // For now, verify the deletion API works for pending addresses
      const saltPrefix = generateSaltPrefix('pending');

      const preregResult = await apiCall(request, 'POST', `/api/v1/admin/orgs/${orgId}/addresses/preregister`, {
        factory: factoryAddress,
        salt_prefix: saltPrefix,
        count: 1,
        note: 'Pending status test'
      });

      expect(preregResult.ok).toBe(true);
      const pendingAddress = preregResult.body.addresses[0];

      // Status should be pending
      expect(pendingAddress.status || 'pending').toBe('pending');
    });
  });
});

test.describe('DeFi Deployment Error Handling', () => {
  let testOrgId: string;

  test.beforeAll(async ({ request }) => {
    const testRunId = `${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    const orgResp = await apiCall(request, 'POST', '/api/v1/admin/orgs', {
      slug: `defi-errors-${testRunId}`,
      name: 'DeFi Error Handling Test'
    });
    if (!orgResp.ok) {
      throw new Error(`Failed to create org: ${JSON.stringify(orgResp.body)}`);
    }
    testOrgId = orgResp.body.id;
  });

  test('DEFI-021: Invalid factory address rejected', async ({ request }) => {
    const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: 'not-an-address',
      salt_prefix: '0x1234',
      count: 1
    });

    expect(result.ok).toBe(false);
    expect(result.status).toBeGreaterThanOrEqual(400);
  });

  // OBSOLETE: CREATE3 factory infrastructure was removed (commit f926200), so
  // /addresses/preregister no longer exists. Test kept for reference, skipped.
  test.skip('DEFI-022: Text salt prefix is allowed (not just hex)', async ({ request }) => {
    // Text salt prefixes are intentionally allowed - they get hashed internally
    // Examples: "myapp-v1", "token-deployment", etc.
    const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: '0x' + '1'.repeat(40),
      salt_prefix: 'text-salt-prefix',
      count: 1
    });

    // Text salt prefixes should be accepted (they're hashed to bytes32)
    expect(result.ok).toBe(true);
    expect(result.body.addresses).toHaveLength(1);
  });

  test('DEFI-023: Zero count rejected', async ({ request }) => {
    const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: '0x' + '1'.repeat(40),
      salt_prefix: '0x1234',
      count: 0
    });

    expect(result.ok).toBe(false);
  });

  test('DEFI-024: Excessive count rejected', async ({ request }) => {
    const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: '0x' + '1'.repeat(40),
      salt_prefix: '0x1234',
      count: 1000 // Excessively large
    });

    // Should either reject or limit the count
    if (result.ok) {
      // If accepted, should be capped
      expect(result.body.addresses.length).toBeLessThanOrEqual(100);
    } else {
      expect(result.status).toBeGreaterThanOrEqual(400);
    }
  });

  test('DEFI-025: Invalid constructor ABI rejected', async ({ request }) => {
    const factoryAddr = '0x' + '1'.repeat(40);

    await apiCall(request, 'PUT', `/api/v1/admin/orgs/${testOrgId}/config/create3`, {
      factory: factoryAddr
    });

    const result = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: factoryAddr,
      salt_prefix: generateSaltPrefix('badabi'),
      count: 1,
      constructor_abi: 'not valid json'
    });

    expect(result.ok).toBe(false);
  });

  // OBSOLETE: CREATE3 factory infrastructure removed.
  test.skip('DEFI-026: Duplicate salt prefix handling', async ({ request }) => {
    const factoryAddr = '0x' + '2'.repeat(40);
    const saltPrefix = generateSaltPrefix('dup');

    await apiCall(request, 'PUT', `/api/v1/admin/orgs/${testOrgId}/config/create3`, {
      factory: factoryAddr
    });

    // First preregistration
    const first = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: factoryAddr,
      salt_prefix: saltPrefix,
      count: 1
    });
    expect(first.ok).toBe(true);

    // Second preregistration with same salt
    const second = await apiCall(request, 'POST', `/api/v1/admin/orgs/${testOrgId}/addresses/preregister`, {
      factory: factoryAddr,
      salt_prefix: saltPrefix,
      count: 1
    });

    // Should either fail (duplicate) or succeed with different derived addresses
    // due to internal salt derivation
    console.log(`Duplicate salt result: ok=${second.ok}, status=${second.status}`);
  });
});
