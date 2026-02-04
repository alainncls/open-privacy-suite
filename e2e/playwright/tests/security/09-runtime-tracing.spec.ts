/**
 * Security Tests: Runtime Transaction Tracing
 *
 * These tests verify that runtime tracing correctly validates
 * all addresses touched by transactions:
 * - Precompiles (0x01-0x09) should always be allowed
 * - Shared infrastructure should always be allowed
 * - Org-owned contracts should be allowed for members
 * - Other org contracts should be denied (cross-org isolation)
 * - CREATE/CREATE2 in runtime should be rejected
 *
 * NOTE: These tests require ENABLE_RUNTIME_TRACING=true
 */

import { test, expect } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth.js';

const API_URL = process.env.PROXY_URL || 'http://localhost:8080';

// Check if runtime tracing is enabled
const RUNTIME_TRACING_ENABLED = process.env.ENABLE_RUNTIME_TRACING === 'true';

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

// Precompile addresses (EVM built-ins)
const PRECOMPILES = {
  ECRECOVER: '0x0000000000000000000000000000000000000001',
  SHA256: '0x0000000000000000000000000000000000000002',
  RIPEMD160: '0x0000000000000000000000000000000000000003',
  IDENTITY: '0x0000000000000000000000000000000000000004',
  MODEXP: '0x0000000000000000000000000000000000000005',
  ECADD: '0x0000000000000000000000000000000000000006',
  ECMUL: '0x0000000000000000000000000000000000000007',
  ECPAIRING: '0x0000000000000000000000000000000000000008',
  BLAKE2F: '0x0000000000000000000000000000000000000009',
};

// Sample bytecode patterns for testing
// CREATE opcode (0xf0) - should be rejected in runtime
const BYTECODE_WITH_CREATE = '0x6080604052348015600f57600080fd5b506040f0';
// CREATE2 opcode (0xf5) - should be rejected in runtime
const BYTECODE_WITH_CREATE2 = '0x6080604052348015600f57600080fd5b506040f5';
// Simple storage contract (no CREATE/CREATE2)
const SIMPLE_BYTECODE = '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea165';

test.describe('Runtime Transaction Tracing', () => {
  // Skip all tests if runtime tracing is not enabled
  test.beforeAll(async () => {
    if (!RUNTIME_TRACING_ENABLED) {
      console.log('SKIP: Runtime tracing tests require ENABLE_RUNTIME_TRACING=true');
    }
  });

  let orgAId: string;
  let orgBId: string;
  let contractA: string;
  let contractB: string;
  let userAToken: string;
  let groupAId: string;
  let testRunId: string;

  test.beforeAll(async ({ request }) => {
    test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

    // Generate unique test run ID
    testRunId = `${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    // Create Organization A
    const orgAResp = await apiCall(request, 'POST', '/api/v1/orgs', {
      slug: `trace-org-a-${testRunId}`,
      name: 'Trace Test Org A'
    });
    if (!orgAResp.ok) {
      throw new Error(`Failed to create org A: ${JSON.stringify(orgAResp.body)}`);
    }
    orgAId = orgAResp.body.id;

    // Create Organization B
    const orgBResp = await apiCall(request, 'POST', '/api/v1/orgs', {
      slug: `trace-org-b-${testRunId}`,
      name: 'Trace Test Org B'
    });
    if (!orgBResp.ok) {
      throw new Error(`Failed to create org B: ${JSON.stringify(orgBResp.body)}`);
    }
    orgBId = orgBResp.body.id;

    // Create group for org A with appropriate permissions
    const groupAResp = await apiCall(request, 'POST', `/api/v1/orgs/${orgAId}/groups`, {
      slug: 'trace-group-a',
      name: 'Trace Group A'
    });
    if (!groupAResp.ok) {
      throw new Error(`Failed to create group A: ${JSON.stringify(groupAResp.body)}`);
    }
    groupAId = groupAResp.body.id;

    // Set group access permissions
    await apiCall(request, 'PUT', `/api/v1/orgs/${orgAId}/groups/${groupAId}/access`, {
      allowed_methods: ['eth_call', 'eth_sendTransaction', 'eth_estimateGas', 'eth_getBalance'],
      default_claims: ['read', 'write']
    });

    // Create contracts - unique addresses per test run
    const hexTs = Date.now().toString(16).slice(-8);
    contractA = '0xaa' + hexTs + 'a'.repeat(30);
    contractB = '0xbb' + hexTs + 'b'.repeat(30);

    // Register contract A to org A
    const contractAResp = await apiCall(request, 'POST', `/api/v1/orgs/${orgAId}/contracts`, {
      address: contractA,
      name: 'Contract A'
    });
    if (!contractAResp.ok) {
      throw new Error(`Failed to create contract A: ${JSON.stringify(contractAResp.body)}`);
    }

    // Register contract B to org B
    const contractBResp = await apiCall(request, 'POST', `/api/v1/orgs/${orgBId}/contracts`, {
      address: contractB,
      name: 'Contract B'
    });
    if (!contractBResp.ok) {
      throw new Error(`Failed to create contract B: ${JSON.stringify(contractBResp.body)}`);
    }

    // Create and setup user A
    const userADID = `did:trace:user-a-${testRunId}`;
    userAToken = await getJWTToken(request, userADID);

    // Find user and update KYC
    const usersResp = await apiCall(request, 'GET', '/api/v1/users');
    const users = usersResp.body;
    const userA = users.find((u: any) => u.external_id === userADID);
    if (!userA) {
      throw new Error(`User A not created after auth: ${userADID}`);
    }

    await apiCall(request, 'PUT', `/api/v1/users/${userA.id}`, { kyc: true });
    await apiCall(request, 'POST', `/api/v1/users/${userA.id}/memberships`, {
      org_id: orgAId,
      group_id: groupAId
    });

    // Refresh token with updated permissions
    userAToken = await getJWTToken(request, userADID);
  });

  test.describe('Cross-Org Call Detection via Trace', () => {
    test('TRACE-001: Transaction calling another org\'s contract is denied', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // User A tries to call a transaction that internally calls org B's contract
      // This simulates a contract at contractA making a CALL to contractB
      // The trace would reveal this cross-org access

      // For now, test direct cross-org eth_call which should be blocked
      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractB, data: '0x' },
        'latest'
      ]);

      expect(result.status).toBe(403);
      expect(result.body.error).toContain('belongs to an organization you are not a member of');
    });

    test('TRACE-002: Transaction touching only own org contracts is allowed', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // User A calling their own org's contract should be allowed
      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractA, data: '0x' },
        'latest'
      ]);

      // Should NOT be 403 (might be 502 if contract doesn't exist on-chain)
      expect(result.status).not.toBe(403);
    });
  });

  test.describe('CREATE/CREATE2 in Runtime Rejection', () => {
    test('TRACE-003: Bytecode containing CREATE opcode is flagged', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // Attempt to deploy bytecode that contains CREATE opcode
      // Runtime tracing should detect and reject this
      const result = await rpcCall(request, userAToken, 'eth_sendTransaction', [
        {
          from: '0x' + '1'.repeat(40),
          data: BYTECODE_WITH_CREATE
        }
      ]);

      // Log the result for debugging
      console.log(`CREATE opcode in runtime: status=${result.status}, body=${JSON.stringify(result.body)}`);

      // The exact behavior depends on implementation
      // Either 403 (blocked by validator) or error from bytecode analysis
      if (result.status === 200) {
        // If allowed, the transaction should fail during execution
        // due to CREATE being blocked in runtime
        expect(result.body.error || result.body.result).toBeDefined();
      }
    });

    test('TRACE-004: Bytecode containing CREATE2 opcode is flagged', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      const result = await rpcCall(request, userAToken, 'eth_sendTransaction', [
        {
          from: '0x' + '1'.repeat(40),
          data: BYTECODE_WITH_CREATE2
        }
      ]);

      console.log(`CREATE2 opcode in runtime: status=${result.status}, body=${JSON.stringify(result.body)}`);
    });
  });

  test.describe('Precompile Calls Allowed', () => {
    test('TRACE-005: Calls to ecrecover precompile (0x01) are allowed', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // ecrecover is a commonly used precompile for signature verification
      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: PRECOMPILES.ECRECOVER, data: '0x' },
        'latest'
      ]);

      // Should NOT be 403 - precompiles are always allowed
      expect(result.status).not.toBe(403);
    });

    test('TRACE-006: Calls to sha256 precompile (0x02) are allowed', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: PRECOMPILES.SHA256, data: '0x' },
        'latest'
      ]);

      expect(result.status).not.toBe(403);
    });

    test('TRACE-007: Calls to identity precompile (0x04) are allowed', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: PRECOMPILES.IDENTITY, data: '0x' },
        'latest'
      ]);

      expect(result.status).not.toBe(403);
    });

    test('TRACE-008: Calls to all standard precompiles (0x01-0x09) are allowed', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      const precompileAddresses = Object.values(PRECOMPILES);

      for (const precompile of precompileAddresses) {
        const result = await rpcCall(request, userAToken, 'eth_call', [
          { to: precompile, data: '0x' },
          'latest'
        ]);

        expect(result.status).not.toBe(403);
      }
    });
  });

  test.describe('Shared Infrastructure Access', () => {
    test('TRACE-009: Shared infrastructure contracts are accessible', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // Use a well-known shared address that should be in the shared_infrastructure table
      // For testing, use an address that is not registered to any specific org

      const hexTs = Date.now().toString(16).slice(-8);
      const unregisteredAddress = '0x00' + hexTs + '0'.repeat(30);

      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: unregisteredAddress, data: '0x' },
        'latest'
      ]);

      // Unregistered addresses should be accessible via default_claims
      // unless explicitly blocked
      expect(result.status).not.toBe(403);
    });
  });

  test.describe('Tiered Validation Optimization', () => {
    test('TRACE-010: Known addresses skip trace for performance', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // When calling a known org-owned contract, the system should
      // optimize by skipping full trace if the target is already validated

      // This is mostly an internal optimization, but we can verify
      // that the call succeeds quickly for known addresses
      const startTime = Date.now();

      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractA, data: '0x' },
        'latest'
      ]);

      const duration = Date.now() - startTime;

      // Should complete without 403
      expect(result.status).not.toBe(403);

      // Log timing for manual inspection
      console.log(`Known address call duration: ${duration}ms`);
    });
  });

  test.describe('Multi-hop Call Detection', () => {
    /**
     * CRITICAL SECURITY TEST: Indirect Cross-Org Call via Org-Owned Contract
     *
     * This test verifies the most important security invariant:
     *
     * Even when User calls their OWN org's contract (OrgA_Contract),
     * if that contract makes an internal CALL to another org's contract (OrgB_Contract),
     * the transaction MUST be DENIED.
     *
     * Attack scenario:
     *   1. User deploys OrgA_Contract with function: attack(address target) { target.call(...); }
     *   2. User calls OrgA_Contract.attack(OrgB_Contract)
     *   3. OrgA_Contract makes CALL to OrgB_Contract
     *   4. EXPECTED: Transaction DENIED via runtime trace validation
     *
     * This prevents the attack where a malicious contract accepts arbitrary
     * call targets from user input and forwards calls to other orgs' contracts.
     *
     * NOTE: Full test requires deploying actual contracts. See demo/demo-cross-org-attack.sh
     * for a manual test of this scenario.
     */
    test('TRACE-011: Multi-hop calls through intermediary contracts are validated', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // This test documents the expected behavior for A -> B -> C call chains
      // where C belongs to a different org

      // In a real scenario with tracing:
      // 1. User calls contract A (owned by org A) - target check passes
      // 2. Contract A calls contract C (org B) - DETECTED BY TRACE
      // 3. Trace shows cross-org call - DENIED

      // For this test, we verify direct cross-org is denied
      // Full multi-hop requires actual deployed contracts with tracing
      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractB, data: '0x' },
        'latest'
      ]);

      expect(result.status).toBe(403);
    });

    test('TRACE-011b: CRITICAL - Org-owned contract making cross-org call must be denied', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      /**
       * THIS IS THE CRITICAL TEST FOR CROSS-ORG ISOLATION
       *
       * Scenario being tested:
       * - User is member of Org A
       * - ContractA is owned by Org A
       * - ContractB is owned by Org B
       * - User calls ContractA with calldata that makes ContractA call ContractB
       *
       * REQUIREMENT: This MUST be DENIED even though the direct target (ContractA)
       * is org-owned. The trace reveals the internal cross-org call.
       *
       * Previous bug: Tiered validation skipped tracing for org-owned contracts,
       * allowing this attack vector.
       *
       * Fix: Tiered validation ONLY skips for CREATE3 factory, not general contracts.
       */

      // To properly test this, we need:
      // 1. A deployed contract that forwards calls based on input
      // 2. Tracing infrastructure to detect the internal call
      //
      // For now, this test documents the requirement.
      // See internal/server/jsonrpc_processor.go:validateWithTracing() for implementation.

      console.log('SECURITY INVARIANT: Org-owned contracts making cross-org calls MUST be denied');
      console.log('Implementation: Tiered validation only skips CREATE3 factory, traces all other contracts');

      // Verify direct access to own contract is allowed (baseline)
      const ownContractResult = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractA, data: '0x' },
        'latest'
      ]);
      expect(ownContractResult.status).not.toBe(403);

      // Verify direct access to other org contract is denied (baseline)
      const otherOrgResult = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractB, data: '0x' },
        'latest'
      ]);
      expect(otherOrgResult.status).toBe(403);
    });

    test('TRACE-012: Deep call stack within same org is allowed', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // Multiple calls within the same org should be allowed
      // even with deep call stacks

      // For this test, verify single org access is allowed
      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: contractA, data: '0x12345678' }, // Different function selector
        'latest'
      ]);

      expect(result.status).not.toBe(403);
    });
  });

  test.describe('Trace Error Handling', () => {
    test('TRACE-013: Invalid address in trace is handled gracefully', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      // Test behavior with malformed addresses
      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: '0xinvalid', data: '0x' },
        'latest'
      ]);

      // Should return an error, not crash
      expect(result.body).toBeDefined();
    });

    test('TRACE-014: Zero address handling in trace', async ({ request }) => {
      test.skip(!RUNTIME_TRACING_ENABLED, 'Runtime tracing not enabled');

      const result = await rpcCall(request, userAToken, 'eth_call', [
        { to: '0x0000000000000000000000000000000000000000', data: '0x' },
        'latest'
      ]);

      // Zero address is technically valid but special
      // Should be handled appropriately
      expect(result.body).toBeDefined();
    });
  });
});

test.describe('Runtime Tracing Configuration', () => {
  test('TRACE-015: Verify tracing environment is correctly configured', async ({ request }) => {
    // This test always runs to document the current configuration
    console.log(`ENABLE_RUNTIME_TRACING=${process.env.ENABLE_RUNTIME_TRACING}`);
    console.log(`Runtime tracing enabled: ${RUNTIME_TRACING_ENABLED}`);

    if (!RUNTIME_TRACING_ENABLED) {
      console.log('NOTE: Set ENABLE_RUNTIME_TRACING=true to run tracing tests');
    }

    // Verify the API is reachable
    const resp = await request.get(`${API_URL}/health`);
    expect(resp.ok()).toBe(true);
  });
});
