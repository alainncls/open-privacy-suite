# Backend Bugs Identified by E2E Security Tests

## 1. Cross-Organization Isolation Not Enforced (CRITICAL)

**Location:** RBAC/Authorization layer

**Failing Tests:**
- `tests/security/01-cross-org-isolation.spec.ts:178` - SECURITY-001: User A cannot access Contract B
- `tests/security/01-cross-org-isolation.spec.ts:190` - SECURITY-002: User B cannot access Contract A
- `tests/security/01-cross-org-isolation.spec.ts:214` - SECURITY-004: eth_getLogs cannot include cross-org contracts
- `tests/security/01-cross-org-isolation.spec.ts:225` - SECURITY-005: eth_getLogs with mixed-org addresses is denied
- `tests/security/01-cross-org-isolation.spec.ts:235` - SECURITY-006: eth_getBalance on cross-org address uses default_claims correctly
- `tests/security/01-cross-org-isolation.spec.ts:265` - SECURITY-008: eth_getCode on cross-org contract is denied
- `tests/security/01-cross-org-isolation.spec.ts:274` - SECURITY-009: eth_getStorageAt on cross-org contract is denied
- `tests/security/01-cross-org-isolation.spec.ts:284` - SECURITY-010: eth_sendTransaction to cross-org contract is denied

**Problem:**
When a contract is registered to Organization B, users from Organization A should NOT be able to:
- Call `eth_call` on that contract
- Get logs via `eth_getLogs` for that contract
- Get balance via `eth_getBalance` for that contract address
- Get code via `eth_getCode` for that contract
- Get storage via `eth_getStorageAt` for that contract
- Send transactions via `eth_sendTransaction` to that contract

**Current Behavior:**
The proxy returns HTTP 200 (success) instead of HTTP 403 (forbidden) when users try to access contracts belonging to organizations they are not members of.

**Expected Behavior:**
Return HTTP 403 with error message "belongs to an organization you are not a member of" when:
1. The target contract address is registered to an organization
2. The requesting user is NOT a member of that organization

**Test Setup:**
- Create Org A and Org B
- Register Contract A to Org A, Contract B to Org B
- Create User A (member of Org A only), User B (member of Org B only)
- User A trying to access Contract B should get 403
- User B trying to access Contract A should get 403

## 2. Multi-Organization User Access Not Properly Separated

**Location:** RBAC/Authorization layer

**Failing Tests:**
- `tests/rbac/23-multi-org-users.spec.ts:218` - access check respects org context
- `tests/rbac/23-multi-org-users.spec.ts:277` - rate limits are org-specific
- `tests/rbac/23-multi-org-users.spec.ts:414` - removing membership from one org does not affect other orgs

**Problem:**
When a user belongs to multiple organizations with different permissions/rate limits:
- Access checks should respect the org context of the request
- Rate limits should be applied per-organization
- Removing membership from one org should not affect access in other orgs

**Current Behavior:**
- Access checks do not properly consider org context
- Rate limits are not being applied per-organization (test expects 10 RPS for org2, but gets 1000)
- Membership removal affects all orgs instead of just the target org

## 3. Server Returns 500 on Invalid UUID Format (Minor)

**Location:** User API endpoint, Organization API endpoint

**Documented in Tests:**
- `tests/security/05-input-validation.spec.ts:119` - SQLI-002: User external_id injection
- `tests/security/06-admin-api-access.spec.ts:32` - ADMIN-003: DELETE /api/v1/orgs/:id

**Problem:**
When an invalid UUID format is provided to endpoints expecting a UUID (like `/api/v1/users/:id` or `/api/v1/orgs/:id`), the server returns HTTP 500 (Internal Server Error) instead of HTTP 400 (Bad Request).

**Expected Behavior:**
Return HTTP 400 with a clear error message like "invalid UUID format" when the ID parameter is not a valid UUID.

---

## Files to Investigate

Based on the RBAC documentation and codebase structure, the cross-org isolation logic should be in:
- `internal/rbac/` - RBAC implementation
- `internal/proxy/` - Proxy request handling
- Look for `OrgContext` or contract ownership checks

## Recommended Fix Approach

1. **For cross-org isolation:**
   - When processing an RPC request that targets a specific contract address
   - Look up which organization owns that contract
   - Compare with the user's organization memberships
   - Deny access if the contract's org is not in the user's membership list

2. **For multi-org users:**
   - Ensure org context is passed through the authorization flow
   - Apply rate limits based on the specific org context, not aggregated
   - Membership operations should be scoped to specific org

3. **For UUID validation:**
   - Add validation at the API layer before attempting database operations
   - Return 400 for invalid format before any DB query
