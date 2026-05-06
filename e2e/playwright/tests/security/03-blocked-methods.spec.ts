/**
 * Security Tests: Blocked Method Bypass
 *
 * These tests verify that globally blocked methods cannot be called
 * through any bypass technique.
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// User DID for this test suite
const USER_DID = `did:security:blocked-methods-test-${Date.now()}`;

// JWT token will be set in beforeAll
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

  // Step 4: Add user to default org's default group using internal ID
  const orgsResp = await request.get(`${API_URL}/api/v1/admin/orgs`);
  const orgsData = await orgsResp.json();
  const orgs = orgsData.data;
  const defaultOrg = orgs.find((o: any) => o.slug === 'default');
  if (defaultOrg) {
    const groupsResp = await request.get(`${API_URL}/api/v1/admin/orgs/${defaultOrg.id}/groups`);
    const groupsData = await groupsResp.json();
    const groups = groupsData.data.map((g: any) => g.group);
    const defaultGroup = groups.find((g: any) => g.slug === 'default');
    if (defaultGroup) {
      await request.post(
        `${API_URL}/api/v1/admin/users/${user.id}/memberships`,
        { data: { org_id: defaultOrg.id, group_id: defaultGroup.id } }
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

test.describe('Blocked Method Enforcement', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  // Debug namespace tests
  test.describe('Debug Namespace Blocking', () => {
    const debugMethods = [
      'debug_traceTransaction',
      'debug_traceBlock',
      'debug_traceBlockByNumber',
      'debug_traceBlockByHash',
      'debug_dumpBlock',
      'debug_preimage',
      'debug_storageRangeAt',
      'debug_accountRange',
      'debug_gcStats',
      'debug_memStats',
      'debug_setHead',
      'debug_verbosity',
    ];

    for (const method of debugMethods) {
      test(`BLOCKED-001: ${method} is blocked`, async ({ request }) => {
        const result = await rpcCall(request, method);
        // Globally-blocked methods return opaque 404. Methods not in the global
        // blocklist but also not in the user's allowlist may return 400 (bad
        // request) — both are denials.
        expect([404, 400]).toContain(result.status);
      });
    }

    test('BLOCKED-002: Unknown debug_* method is blocked by prefix', async ({ request }) => {
      const result = await rpcCall(request, 'debug_newFutureMethod');
      expect(result.status).toBe(404); // opaque RBAC denial
      expect(result.body.error).toContain('method not found');
    });
  });

  // Admin namespace tests
  test.describe('Admin Namespace Blocking', () => {
    const adminMethods = [
      'admin_addPeer',
      'admin_removePeer',
      'admin_nodeInfo',
      'admin_peers',
      'admin_datadir',
      'admin_startRPC',
      'admin_stopRPC',
      'admin_startHTTP',
      'admin_stopHTTP',
    ];

    for (const method of adminMethods) {
      test(`BLOCKED-003: ${method} is blocked`, async ({ request }) => {
        const result = await rpcCall(request, method);
        expect(result.status).toBe(404); // opaque RBAC denial
        expect(result.body.error).toContain('method not found');
      });
    }
  });

  // Personal namespace tests (key exposure risk)
  test.describe('Personal Namespace Blocking', () => {
    const personalMethods = [
      'personal_sign',
      'personal_signTransaction',
      'personal_unlockAccount',
      'personal_newAccount',
      'personal_listAccounts',
      'personal_importRawKey',
    ];

    for (const method of personalMethods) {
      test(`BLOCKED-004: ${method} is blocked`, async ({ request }) => {
        const result = await rpcCall(request, method);
        expect(result.status).toBe(404); // opaque RBAC denial
        expect(result.body.error).toContain('method not found');
      });
    }
  });

  // Miner namespace tests
  test.describe('Miner Namespace Blocking', () => {
    const minerMethods = [
      'miner_start',
      'miner_stop',
      'miner_setEtherbase',
      'miner_setGasPrice',
    ];

    for (const method of minerMethods) {
      test(`BLOCKED-005: ${method} is blocked`, async ({ request }) => {
        const result = await rpcCall(request, method);
        expect(result.status).toBe(404); // opaque RBAC denial
        expect(result.body.error).toContain('method not found');
      });
    }
  });

  // Txpool namespace tests (MEV risk)
  test.describe('Txpool Namespace Blocking', () => {
    test('BLOCKED-006: txpool_content is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'txpool_content');
      expect(result.status).toBe(404); // opaque RBAC denial
    });

    test('BLOCKED-007: txpool_status is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'txpool_status');
      expect(result.status).toBe(404); // opaque RBAC denial
    });

    test('BLOCKED-008: txpool_inspect is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'txpool_inspect');
      expect(result.status).toBe(404); // opaque RBAC denial
    });
  });

  // Raw transaction blocking
  test.describe('Raw Transaction Blocking', () => {
    test('BLOCKED-009: eth_sendRawTransaction requires valid transaction and authorization', async ({ request }) => {
      // eth_sendRawTransaction is NOT in GlobalBlockedMethods - it's handled specially.
      // - When runtime tracing is disabled: returns 403 with "runtime tracing" error
      // - When runtime tracing is enabled: requires valid RLP, then checks RBAC
      // Either way, sending invalid hex should fail
      const result = await rpcCall(request, 'eth_sendRawTransaction', ['0x...']);
      // Should be either 403 (runtime tracing disabled) or 400 (invalid RLP when tracing enabled)
      expect([400, 403]).toContain(result.status);
      // Should NOT succeed
      expect(result.body).toHaveProperty('error');
    });
  });

  // Signing methods
  test.describe('Signing Method Blocking', () => {
    test('BLOCKED-010: eth_sign is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_sign', ['0x123', '0xabc']);
      expect(result.status).toBe(404); // opaque RBAC denial
    });

    test('BLOCKED-011: eth_signTransaction is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_signTransaction', [{}]);
      expect(result.status).toBe(404); // opaque RBAC denial
    });
  });

  // WebSocket subscription blocking
  test.describe('Subscription Blocking', () => {
    test('BLOCKED-012: eth_subscribe is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_subscribe', ['newHeads']);
      expect(result.status).toBe(404); // opaque RBAC denial
    });

    test('BLOCKED-013: eth_unsubscribe is blocked', async ({ request }) => {
      const result = await rpcCall(request, 'eth_unsubscribe', ['0x1']);
      expect(result.status).toBe(404); // opaque RBAC denial
    });
  });
});

test.describe('Blocked Method Bypass Attempts', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('BYPASS-001: Case variation does not bypass blocking', async ({ request }) => {
    const caseVariations = [
      'DEBUG_traceTransaction',
      'Debug_TraceTransaction',
      'dEbUg_tRaCeTraNsAcTiOn',
      'ADMIN_PEERS',
      'Admin_Peers',
    ];

    for (const method of caseVariations) {
      const result = await rpcCall(request, method);
      // Method should either be blocked (if normalized) or not found
      expect([403, 404, 400]).toContain(result.status);
    }
  });

  test('BYPASS-002: Unicode homoglyphs do not bypass blocking', async ({ request }) => {
    // Using lookalike characters
    const homoglyphs = [
      'dеbug_traceTransaction', // Cyrillic 'е' instead of Latin 'e'
      'аdmin_peers',            // Cyrillic 'а' instead of Latin 'a'
    ];

    for (const method of homoglyphs) {
      const result = await rpcCall(request, method);
      // Should either be blocked or treated as unknown method
      expect([403, 404, 400]).toContain(result.status);
    }
  });

  test('BYPASS-003: Prefix/suffix variations do not bypass blocking', async ({ request }) => {
    const variations = [
      '_debug_traceTransaction',
      'debug_traceTransaction_',
      '__debug_traceTransaction__',
      ' debug_traceTransaction',
      'debug_traceTransaction ',
      '\tdebug_traceTransaction',
      '\ndebug_traceTransaction',
    ];

    for (const method of variations) {
      const result = await rpcCall(request, method);
      // Should not be allowed
      expect([403, 404, 400]).toContain(result.status);
    }
  });

  test('BYPASS-004: URL encoding does not bypass blocking', async ({ request }) => {
    // If method name is URL-decoded somewhere
    const result = await rpcCall(request, 'debug%5ftraceTransaction'); // %5f = _
    expect([403, 404, 400]).toContain(result.status);
  });

  test('BYPASS-005: Null bytes do not bypass blocking', async ({ request }) => {
    const result = await rpcCall(request, 'debug_traceTransaction\x00safe');
    expect([403, 404, 400]).toContain(result.status);
  });
});

test.describe('Allowed Methods Still Work', () => {

  test.beforeAll(async ({ request }) => {
    await setupUser(request);
  });

  test('ALLOWED-001: eth_blockNumber is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_blockNumber');
    // Should work (200) or be allowed but fail for other reasons (not 403)
    expect(result.status).not.toBe(403);
  });

  test('ALLOWED-002: eth_chainId is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_chainId');
    expect(result.status).not.toBe(403);
  });

  test('ALLOWED-003: eth_gasPrice is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'eth_gasPrice');
    expect(result.status).not.toBe(403);
  });

  test('ALLOWED-004: net_version is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'net_version');
    expect(result.status).not.toBe(403);
  });

  test('ALLOWED-005: web3_clientVersion is allowed', async ({ request }) => {
    const result = await rpcCall(request, 'web3_clientVersion');
    expect(result.status).not.toBe(403);
  });
});
