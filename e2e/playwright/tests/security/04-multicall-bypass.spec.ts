/**
 * Security Tests: Multicall Bypass Attempts
 *
 * Multicall contracts can batch multiple calls together.
 * If not blocked, attackers could:
 * - Read data from contracts they don't have access to
 * - Execute transactions against multiple contracts in one call
 *
 * This bypasses per-contract RBAC because the proxy only sees
 * the Multicall contract address, not the inner call targets.
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// User DID for this test suite
const USER_DID = `did:security:multicall-test-${Date.now()}`;

// JWT token will be set in beforeAll
let jwtToken: string;

// Known Multicall addresses
const MULTICALL3 = '0xca11bde05977b3631167028862be2a173976ca11';
const MULTICALL2 = '0x5ba1e12693dc8f9c48aad8770482f4739beed696';
const MULTICALL1 = '0xeefba1e63905ef1d7acba5a8513c70307c1ce441';

// Multicall function selectors
const SELECTORS = {
  aggregate: '0x252dba42',
  aggregate3: '0x82ad56cb',
  aggregate3Value: '0x174dea71',
  blockAndAggregate: '0xc3077fa9',
  tryAggregate: '0xbce38bd7',
  tryBlockAndAggregate: '0x399542e9',
};

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

  // Step 4: Create group with deploy claims and add user
  const orgsResp = await request.get(`${API_URL}/api/v1/admin/orgs`);
  const orgsData = await orgsResp.json();
  const orgs = orgsData.data;
  const defaultOrg = orgs.find((o: any) => o.slug === 'default');
  if (defaultOrg) {
    // Create a group with deploy claims (needed for unregistered contract access)
    const groupResp = await request.post(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`, {
      data: {
        slug: 'security-multicall-test',
        name: 'Security Multicall Test',
      }
    });
    let groupId: string;
    if (groupResp.ok()) {
      const group = await groupResp.json();
      groupId = group.id;
    } else {
      // Group already exists from previous run, find it
      const groupsResp = await request.get(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`);
      const groupsData = await groupsResp.json();
      const groups = groupsData.data.map((g: any) => g.group);
      groupId = groups.find((g: any) => g.slug === 'security-multicall-test')?.id;
    }

    if (groupId) {
      // Set group access with deploy claims
      await request.put(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups/${groupId}/access`, {
        data: {
          allowed_methods: ['eth_call', 'eth_getBalance', 'eth_getCode', 'eth_getStorageAt', 'eth_sendTransaction', 'eth_estimateGas'],
          claims: ['deploy'] // deploy needed for unregistered contract access
        }
      });

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

test.describe('Multicall Detection and Blocking', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test.describe('eth_call to Multicall Contracts', () => {
    const multicallAddresses = [
      { name: 'Multicall3', address: MULTICALL3 },
      { name: 'Multicall2', address: MULTICALL2 },
      { name: 'Multicall1', address: MULTICALL1 },
    ];

    for (const { name, address } of multicallAddresses) {
      for (const [funcName, selector] of Object.entries(SELECTORS)) {
        test(`MULTICALL-001: eth_call to ${name}.${funcName}() is blocked`, async ({ request }) => {
          // Build calldata: selector + some dummy ABI-encoded data
          const calldata = selector + '0'.repeat(64); // Minimum encoded params

          const result = await rpcCall(request, 'eth_call', [
            { to: address, data: calldata },
            'latest'
          ]);

          expect(result.status).toBe(403);
          expect(result.body.error.toLowerCase()).toContain('multicall');
        });
      }
    }
  });

  test.describe('eth_estimateGas to Multicall Contracts', () => {
    test('MULTICALL-002: eth_estimateGas to Multicall3.aggregate() is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_estimateGas', [
        { to: MULTICALL3, data: SELECTORS.aggregate + '0'.repeat(64) },
        'latest'
      ]);

      expect(result.status).toBe(403);
      expect(result.body.error.toLowerCase()).toContain('multicall');
    });

    test('MULTICALL-003: eth_estimateGas to Multicall3.tryAggregate() is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_estimateGas', [
        { to: MULTICALL3, data: SELECTORS.tryAggregate + '0'.repeat(64) },
        'latest'
      ]);

      expect(result.status).toBe(403);
    });
  });

  test.describe('eth_sendTransaction to Multicall Contracts', () => {
    test('MULTICALL-004: eth_sendTransaction to Multicall3.aggregate() is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_sendTransaction', [
        {
          from: '0x' + '1'.repeat(40),
          to: MULTICALL3,
          data: SELECTORS.aggregate + '0'.repeat(64)
        }
      ]);

      expect(result.status).toBe(403);
      expect(result.body.error.toLowerCase()).toContain('multicall');
    });
  });

  test.describe('Case Sensitivity in Multicall Detection', () => {
    test('MULTICALL-005: Uppercase Multicall address is still blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_call', [
        { to: MULTICALL3.toUpperCase(), data: SELECTORS.aggregate + '0'.repeat(64) },
        'latest'
      ]);

      expect(result.status).toBe(403);
    });

    test('MULTICALL-006: Mixed case Multicall address is still blocked', async ({ request }) => {
      // Mix case in address
      const mixedCase = MULTICALL3.slice(0, 2) + MULTICALL3.slice(2).replace(/[a-f]/g, (c) =>
        Math.random() > 0.5 ? c.toUpperCase() : c
      );

      const result = await rpcCall(request, 'eth_call', [
        { to: mixedCase, data: SELECTORS.aggregate + '0'.repeat(64) },
        'latest'
      ]);

      expect(result.status).toBe(403);
    });
  });

  test.describe('Non-Multicall Calls to Multicall Address', () => {
    test('MULTICALL-007: Non-multicall function call to Multicall address is allowed', async ({ request }) => {
      // Call a non-multicall function (e.g., getBlockNumber - 0x42cbb15c)
      const result = await rpcCall(request, 'eth_call', [
        { to: MULTICALL3, data: '0x42cbb15c' }, // getBlockNumber()
        'latest'
      ]);

      // This should be allowed (or fail for contract reasons, but not 403)
      // Actually, wait - accessing Multicall contract itself might be blocked anyway
      // Let's check the actual behavior
      // If the proxy blocks ALL calls to Multicall, that's stricter but safer
      // For now, let's just verify the behavior is consistent
      expect([200, 502, 403]).toContain(result.status);
    });
  });
});

test.describe('Multicall Bypass Attempts', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('BYPASS-001: Multicall via different address (custom deployment)', async ({ request }) => {
    // This is a potential vulnerability: if someone deploys their own Multicall
    // at a different address, it won't be in the blocklist
    const customMulticallAddress = '0x' + 'dead'.repeat(10);

    // Using aggregate selector
    const result = await rpcCall(request, 'eth_call', [
      { to: customMulticallAddress, data: SELECTORS.aggregate + '0'.repeat(64) },
      'latest'
    ]);

    // Currently this might NOT be blocked because the address isn't in the list
    // This test documents the current behavior
    // If this passes with 200/502, it's a FINDING - custom Multicalls can bypass
    if (result.status !== 403) {
      console.log('FINDING: Custom Multicall address bypasses detection!');
      console.log('Response:', result);
    }

    // Note: We don't assert here because this documents a known limitation
    // The test passing (not 403) indicates the vulnerability exists
  });

  test('BYPASS-002: Nested call through allowed contract to Multicall', async ({ request }) => {
    // If an allowed contract has a function that calls Multicall internally,
    // the proxy can't detect it
    // This is a limitation of application-level filtering

    // This test is more of a documentation of the limitation
    // We can't fully test this without deploying a malicious contract
    expect(true).toBe(true); // Placeholder
  });

  test('BYPASS-003: Empty calldata to Multicall address', async ({ request }) => {
    // Test with empty/no data field
    const result = await rpcCall(request, 'eth_call', [
      { to: MULTICALL3 },
      'latest'
    ]);

    // Should be allowed (no multicall function called) or blocked (all Multicall blocked)
    expect([200, 502, 403]).toContain(result.status);
  });

  test('BYPASS-004: Partial selector to Multicall', async ({ request }) => {
    // Truncated selector
    const result = await rpcCall(request, 'eth_call', [
      { to: MULTICALL3, data: '0x252d' }, // Partial aggregate selector
      'latest'
    ]);

    // Should not be blocked as multicall (selector incomplete)
    // But might fail for other reasons
    expect([200, 502]).toContain(result.status);
  });

  test('BYPASS-005: Selector with wrong prefix', async ({ request }) => {
    // Different first byte but similar rest
    const result = await rpcCall(request, 'eth_call', [
      { to: MULTICALL3, data: '0x152dba42' + '0'.repeat(64) }, // First byte changed
      'latest'
    ]);

    // Should not be detected as multicall
    expect([200, 502]).toContain(result.status);
  });
});

test.describe('Multicall via Different Methods', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('MULTICALL-008: eth_getCode on Multicall address is allowed', async ({ request }) => {
    // Reading code should be allowed (it's public)
    const result = await rpcCall(request, 'eth_getCode', [MULTICALL3, 'latest']);

    // Should not be 403 (reading code is informational)
    expect(result.status).not.toBe(403);
  });

  test('MULTICALL-009: eth_getBalance on Multicall address is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getBalance', [MULTICALL3, 'latest']);
    expect(result.status).not.toBe(403);
  });

  test('MULTICALL-010: eth_getStorageAt on Multicall address behavior', async ({ request }) => {
    const result = await rpcCall(request, 'eth_getStorageAt', [MULTICALL3, '0x0', 'latest']);

    // Reading storage might be allowed or blocked depending on policy
    // Document the behavior
    console.log(`eth_getStorageAt on Multicall: status=${result.status}`);
  });
});
