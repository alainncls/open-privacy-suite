# Security Audit — February 2026

**Scope**: Full attack-surface review of the privacy proxy (auth, RBAC, JSON-RPC processing, DB, ETH linking, runtime tracing).
**Prior audits cross-referenced**: `SECURITY-REVIEW.md` (Jan 2025), `SECURITY_FINDINGS.md` (Jan 30 2026), `SECURITY_DATA_EXPOSURE.md` (Feb 2 2026).

Severity key: **CRITICAL** = bypass gives unrestricted access or state mutation; **HIGH** = targeted bypass or data leak; **MEDIUM** = design weakness exploitable under specific conditions; **LOW** = hardening / defense-in-depth gap.

---

## Attack Vector 1: Bypass Authentication

### 1.1 Mock Auth Bypass — CRITICAL (PREVIOUSLY KNOWN)

**File**: `internal/server/auth.go:182`
**Issue**: When `MOCK_AUTH=true`, the ZK-proof verification is entirely skipped and a hardcoded DID is injected. If this flag leaks to production, any request is treated as authenticated.
**Attack**: Send any request to the proxy — no credentials needed.
**Status**: Documented in `SECURITY_FINDINGS.md` V-01. Requires build-time / deploy-time enforcement.

### 1.2 JWT Secret Auto-Generation — CRITICAL (PREVIOUSLY KNOWN)

**File**: `internal/server/auth.go` (JWT initialization)
**Issue**: If `JWT_SECRET` is not set, the server generates a random secret and continues. This means a restart rotates all tokens, but more importantly it means the operator may not realize auth is running on an ephemeral secret.
**Status**: Documented in `SECURITY_FINDINGS.md` V-02. Needs startup-abort when secret is missing.

### 1.3 Mock Signature Bypass for ETH Linking — HIGH (PREVIOUSLY KNOWN)

**File**: `internal/server/eth_link.go`
**Issue**: `MOCK_SIGNATURES=true` skips EIP-191 signature verification. An attacker can link any ETH address to their DID without holding the private key.
**Impact with param constraints**: Once you own the link, `"self"` param rules pass for that address — full impersonation.
**Status**: Same class as 1.1. Needs build-time gating.

### 1.4 Localhost Admin Middleware — Broad IP Match — HIGH (PREVIOUSLY KNOWN)

**File**: `internal/server/middleware.go`
**Issue**: Admin API is guarded by IP allowlist that accepts `127.0.0.1`, `::1`, and various loopback representations. Depending on deployment topology, container-to-host traffic may match.
**Status**: Documented in `SECURITY_FINDINGS.md` V-04. Needs explicit admin auth tokens.

---

## Attack Vector 2: Escalate RBAC Permissions

### 2.1 Hierarchy Claims Intersection — Empty Claims Don't Narrow — HIGH (NEW)

**File**: `internal/rbac/resolver.go:322-326`
```go
if result.Claims == nil {
    result.Claims = access.Claims
} else if len(access.Claims) > 0 {
    result.Claims = intersectClaims(result.Claims, access.Claims)
}
```
**Issue**: When a child group has `Claims: []` (explicitly empty), `len(access.Claims) > 0` is false, so the parent's broader claims are preserved. An admin who sets a child group to "no default claims" expects it to **narrow** the parent, but it's a no-op.
**Attack**: Place a user in a hierarchy where the child group has empty claims → user inherits the parent's full claim set instead of being restricted.
**Same pattern applies to `AllowedMethods`** at line 315-319.
**Fix**: Distinguish `nil` (unset / inherit) from `[]` (explicitly empty / deny-all). If `access.Claims != nil && len(access.Claims) == 0`, set `result.Claims = []Claim{}`.

### 2.2 Functions `nil` vs Empty Slice Confusion — MEDIUM (NEW)

**File**: `internal/rbac/models.go:338`
```go
if len(access.Functions) == 0 {
    return true // all functions allowed
}
```
**Issue**: Both `nil` (no restriction set) and `[]FunctionRule{}` (explicitly "no functions allowed") evaluate to `len == 0`, meaning "all functions allowed". An admin who removes all function selectors from a grant (emptying the array) unintentionally grants access to ALL functions.
**Fix**: Use a pointer or a separate boolean field to distinguish "unrestricted" from "none".

### 2.3 Default Claims Escape for Unregistered Contracts — MEDIUM (PREVIOUSLY KNOWN, REFINED)

**File**: `internal/rbac/org_context.go:224-226`
```go
if ownerOrgID == "" {
    // Contract is truly public (not registered anywhere) - allow default_claims
    return nil
}
```
**Issue**: Any contract not registered in the RBAC system is treated as "public" and accessible via default claims (read+write by default). Combined with the deployment race condition (known gap), a freshly deployed contract is accessible to everyone with default write claims until it's registered.
**Status**: Partially documented. The deployment race is noted in project docs; the default claims amplification is the refinement.

### 2.4 Cache Invalidation Race Condition — MEDIUM (NEW)

**File**: `internal/rbac/resolver.go` (cache layer), `internal/db/rbac_store_cache.go`
**Issue**: When permissions change (grant revoked, group updated), the cache is invalidated by deleting the entry. But between the delete and the next resolution, a concurrent request that started before the delete can re-populate the cache with stale data (it read the old entry before invalidation, computes old permissions, and writes them back).
**Attack**: Time a request to coincide with a permission revocation — the stale cached permissions survive the invalidation.
**Fix**: Use a version counter or "invalidated_at" timestamp; reject cache writes that are older than the last invalidation.

---

## Attack Vector 3: Bypass Function-Level / Parameter-Level Controls

### 3.1 Short or Missing Selector Bypasses Function Restrictions — HIGH (NEW)

**File**: `internal/rbac/access.go:606`
```go
if req.FunctionSelector != "" {
    if !perms.HasFunctionSelector(addr, req.FunctionSelector) { ... }
    // param constraint checks ...
}
```
**Issue**: The entire function-selector and parameter-constraint block is gated on `req.FunctionSelector != ""`. If the function selector is not extracted (calldata < 4 bytes, or `extractTargetAddress` doesn't set it), the check is skipped entirely. The user still has contract-level access — they just bypass function-level restrictions.
**Attack**: Send `eth_call` with a `data` field of `"0x"` or 1-3 bytes. The selector extraction returns `""`, so function/param checks are skipped. The call still reaches the node, which may execute `fallback()` or `receive()`. If the contract's fallback has sensitive logic, it runs unchecked.
**Fix**: When `access.Functions` is non-empty (function restrictions exist), require a valid selector. Deny if the selector is empty.

### 3.2 Calldata Selector vs Claimed Selector Not Cross-Verified — HIGH (NEW)

**File**: `internal/rbac/access.go:606-615`, `param_validator.go:38`
**Issue**: `req.FunctionSelector` is extracted from the `data` field early in the pipeline, and `GetFunctionRule(addr, req.FunctionSelector)` looks up the matching rule. Then `ValidateParamRules` calls `parsedABI.MethodById(calldata[:4])` independently. These two selectors come from the same calldata, so they should match — but there's no explicit verification.
**Risk assessment**: Currently low because both derive from the same `data` field. But if any code path sets `req.FunctionSelector` from a source other than calldata (e.g., from the method name in a future refactor), the param validator would check the wrong function's constraints.
**Fix**: Add a guard in `ValidateParamRules`: verify `calldata[:4]` matches `rule.Selector`.

### 3.3 `extractCalldata` Silently Returns nil — MEDIUM (NEW)

**File**: `internal/rbac/access.go:953-977`
```go
func extractCalldata(method string, params []any) []byte {
    if method != "eth_sendTransaction" && method != "eth_call" && method != "eth_estimateGas" {
        return nil
    }
    // ... if any field is missing/wrong, returns nil
}
```
**Issue**: When `extractCalldata` returns `nil`, the parameter constraint block at line 622-627 correctly denies with "calldata required". But if `req.Calldata` was pre-populated (e.g., from `processRawTransaction`), that path is used instead. The concern is: what happens when a method type isn't in the 3-method allowlist but still targets a contract?
**For example**: `eth_getStorageAt` targets a contract and could read sensitive storage, but it's not in the calldata extraction list — and it has no function selector concept, so all function-level and param-level restrictions are meaningless for it.
**Status**: `eth_getStorageAt` bypass is acknowledged in the plan as a known limitation. This note is a reminder that any new constrained methods must be added to the extraction list.

### 3.4 `eth_getStorageAt` Bypasses All Contract-Level Function Controls — MEDIUM (PREVIOUSLY KNOWN)

**File**: `internal/rbac/access.go:831-837`
**Issue**: `eth_getStorageAt` requires only `read` claim on the contract. It can read any storage slot, including data that should be gated behind param constraints (e.g., `balanceOf` result is in a mapping slot that can be read directly).
**Status**: Acknowledged as known limitation for PoC.

---

## Attack Vector 4: Harm Blockchain State via Transaction Manipulation

### 4.1 Simple Value Transfer Skips Runtime Tracing — HIGH (NEW)

**File**: `internal/server/jsonrpc_processor.go:352-359`
```go
// "100% safe because... Contract receive()/fallback() with empty calldata is minimal risk"
if isSimpleValueTransfer(data) {
    return nil
}
```
**Issue**: The comment claims `receive()`/`fallback()` with empty calldata is "minimal risk". This is incorrect: a contract's `receive()` function **can make external calls** to other contracts, including cross-org contracts. By sending ETH with empty calldata, an attacker triggers `receive()` which may call into contracts belonging to other organizations — bypassing the cross-org isolation that runtime tracing is supposed to enforce.
**Attack**: Deploy a contract with a `receive() external payable` that calls `otherOrgContract.someFunction()`. Send a simple value transfer to it. Tracing is skipped, so the cross-org call is never detected.
**Fix**: Only skip tracing for transfers to EOAs (check with `eth_getCode`). For transfers to contracts, always trace.

### 4.2 Trace Result `nil` Treated as Success — MEDIUM (NEW)

**File**: `internal/server/jsonrpc_processor.go:371-373`
```go
if traceResult == nil {
    return nil // Tracing not applicable
}
```
**Issue**: If `TraceTransaction` returns `(nil, nil)` — no result, no error — the transaction is allowed. This could happen if the tracer implementation has a bug or edge case where it returns nil for certain inputs.
**Current risk**: Depends entirely on the tracer implementation. If the tracer is well-tested this is low risk. But it's a fail-open design.
**Fix**: Fail-closed — if trace was requested but returned nil, deny.

### 4.3 Deployment Race Condition — HIGH (PREVIOUSLY KNOWN)

**Issue**: When a contract is deployed via regular CREATE/CREATE2 (not CREATE3), there's a window where the contract exists on-chain but isn't registered in RBAC. During this window, any user with default write claims can interact with it.
**Status**: Documented in project memory and security docs. Planned fix: pre-compute CREATE address, pre-register to deployer's org, finalize on receipt, clean up on revert.

---

## Attack Vector 5: Access Restricted Data

### 5.1 ETH Address Hijacking via ON CONFLICT Re-Linking — CRITICAL (NEW)

**File**: `internal/db/db.go:338-349`
```sql
INSERT INTO eth_address_links (did, eth_address, signature, message_hash)
VALUES ($1, $2, $3, $4)
ON CONFLICT (eth_address) DO UPDATE SET
    did = excluded.did, ..., revoked = false, revoked_at = NULL
```
**Issue**: Any user who can produce a valid EIP-191 signature for an ETH address can re-link it to their own DID, **stealing it from the current owner**. The `ON CONFLICT` clause silently re-assigns the address and clears the revocation state.
**Attack**:
1. Alice links address `0xAAA` to her DID (she holds the private key)
2. Bob also holds the private key (shared key, or compromised key)
3. Bob links `0xAAA` to his DID — Alice's link is silently overwritten
4. Bob now passes `"self"` param constraints for `0xAAA`
5. If Alice had contract grants scoped to `0xAAA`, Bob can now act as Alice

**Impact with param constraints**: This is amplified by the new `"self"` param rules — hijacking an address now also hijacks all parameter-constrained permissions.
**Fix**: Reject re-linking if the address is already linked to a different DID (unless the current owner explicitly unlinks it first). The `ON CONFLICT` should `DO NOTHING` or raise an error when `did != excluded.did`.

### 5.2 ON CONFLICT Clears Revocation — Audit Trail Erasure — MEDIUM (NEW)

**File**: `internal/db/db.go:346`
```sql
revoked = false, revoked_at = NULL
```
**Issue**: The same `ON CONFLICT` clause resets `revoked = false`. If an admin revoked an address link (e.g., because it was compromised), the address holder can simply re-link it and the revocation is silently undone. No audit trail of the revocation survives.
**Fix**: Do not clear revocation flags on re-link. Require explicit admin action to un-revoke.

### 5.3 Historical State Queries — Incomplete Detection — MEDIUM (PREVIOUSLY KNOWN)

**File**: `internal/rbac/access.go:1256-1258`
```go
if method != "eth_call" && method != "eth_getStorageAt" {
    return false, ""
}
```
**Issue**: Historical state detection only covers `eth_call` and `eth_getStorageAt`. Other methods like `eth_getBalance`, `eth_getTransactionCount`, and `eth_getCode` also accept block parameters and can leak historical state, but aren't checked.
**Status**: Documented in `SECURITY_DATA_EXPOSURE.md` Finding 5.

### 5.4 `eth_getLogs` Topic Filtering Not Enforced — LOW (PREVIOUSLY KNOWN)

**Issue**: `eth_getLogs` validates address filters but not topic filters. A user with read access to a contract can query ALL events, even if they should only see events relevant to them.
**Status**: Acknowledged as future work.

---

## Attack Vector 6: Harm Infrastructure

### 6.1 Batch Request Detection — Fragile Check — LOW (NEW)

**File**: `internal/proxy/proxy.go:77-81`
```go
func IsBatchRequest(body []byte) bool {
    trimmed := bytes.TrimSpace(body)
    return len(trimmed) > 0 && trimmed[0] == '['
}
```
**Issue**: The batch detection is a simple `[` prefix check after trimming whitespace. This is actually robust for well-formed JSON — any JSON array starts with `[`. However, it's checked BEFORE JSON parsing, so malformed inputs like `[garbage` are rejected as "batch" rather than parsed and producing a proper JSON error.
**Risk**: Minimal in practice. This is defense-in-depth for the existing batch block.

### 6.2 Rate Limiter TOCTOU — LOW (NEW)

**Issue**: Rate limiting is checked before the request is forwarded to the node. Between the check and the forward, the rate limit state isn't atomically updated with the actual request execution. Under high concurrency, more requests than the limit can slip through.
**Risk**: Low for PoC. In production, use atomic increment-and-check.

### 6.3 Refresh Token Rotation Race Condition — LOW (PREVIOUSLY KNOWN)

**File**: `internal/server/auth.go` (token refresh handler)
**Issue**: If two concurrent requests use the same refresh token, both may succeed before the old token is revoked, issuing two new token pairs.
**Status**: Documented in `SECURITY_FINDINGS.md`.

---

## Attack Vector 7: Cross-Organization Isolation Bypass

### 7.1 Non-Atomic Cross-Org Contract Access Checks — MEDIUM (NEW)

**File**: Multiple — `org_context.go`, `access.go`
**Issue**: Cross-org isolation involves multiple sequential checks: resolve org membership, look up contract ownership, check permissions. These are not wrapped in a database transaction, so a contract could be re-assigned to a different org between the ownership check and the permission check.
**Attack**: Unlikely in normal operation but possible under adversarial admin timing. Admin moves a contract from org-A to org-B while a user from org-A is mid-request.
**Fix**: Accept as PoC limitation. In production, use snapshot-isolation reads.

### 7.2 Trace Validation Doesn't Recheck After Permission Changes — LOW (NEW)

**Issue**: Runtime trace validation checks cross-org isolation at trace time. If permissions change between trace and actual execution (trace uses `debug_traceCall`, actual execution is the real `eth_sendTransaction`), the state may differ.
**Risk**: Very small window. The trace and forward happen in the same request cycle.

---

## Summary Table

| # | Finding | Severity | Status | Vector |
|---|---------|----------|--------|--------|
| 1.1 | Mock auth bypass | CRITICAL | Previously known | Auth |
| 1.2 | JWT secret auto-gen | CRITICAL | Previously known | Auth |
| 1.3 | Mock signature bypass | HIGH | Previously known | Auth |
| 1.4 | Localhost admin IP match | HIGH | Previously known | Auth |
| 2.1 | Empty claims don't narrow hierarchy | HIGH | **NEW** | RBAC |
| 2.2 | nil vs empty Functions confusion | MEDIUM | **NEW** | RBAC |
| 2.3 | Default claims for unregistered contracts | MEDIUM | Known, refined | RBAC |
| 2.4 | Cache invalidation race | MEDIUM | **NEW** | RBAC |
| 3.1 | Empty selector bypasses function checks | HIGH | **NEW** | Param |
| 3.2 | Selector cross-verification missing | HIGH | **NEW** | Param |
| 3.3 | extractCalldata silent nil | MEDIUM | **NEW** | Param |
| 3.4 | eth_getStorageAt bypasses param rules | MEDIUM | Known | Param |
| 4.1 | Simple transfer skips tracing | HIGH | **NEW** | State |
| 4.2 | Nil trace result = success | MEDIUM | **NEW** | State |
| 4.3 | Deployment race condition | HIGH | Previously known | State |
| 5.1 | ETH address hijacking via re-link | CRITICAL | **NEW** | Data |
| 5.2 | ON CONFLICT clears revocation | MEDIUM | **NEW** | Data |
| 5.3 | Incomplete historical state detection | MEDIUM | Previously known | Data |
| 5.4 | eth_getLogs topic filtering | LOW | Previously known | Data |
| 6.1 | Batch detection fragility | LOW | **NEW** | Infra |
| 6.2 | Rate limiter TOCTOU | LOW | **NEW** | Infra |
| 6.3 | Refresh token race | LOW | Previously known | Infra |
| 7.1 | Non-atomic cross-org checks | MEDIUM | **NEW** | Isolation |
| 7.2 | Trace doesn't recheck perms | LOW | **NEW** | Isolation |

---

## Recommended Priority for Fixes

**Immediate (before any shared deployment):**
1. **5.1** — ETH address hijacking. Change `ON CONFLICT` to reject re-linking to a different DID.
2. **2.1** — Empty claims hierarchy bypass. Distinguish `nil` from `[]` in resolver intersection.
3. **3.1** — Empty selector bypass. Require valid selector when function restrictions exist.
4. **4.1** — Simple transfer tracing skip. Check `eth_getCode` before skipping trace.

**Short-term:**
5. **3.2** — Add selector cross-verification in param validator.
6. **2.2** — nil vs empty Functions semantic fix.
7. **5.2** — Don't clear revocation on re-link.
8. **4.2** — Fail-closed on nil trace result.

**When moving toward production:**
9. **1.1, 1.2, 1.3** — Build-time enforcement of mock/secret flags.
10. **1.4** — Replace IP-based admin auth with token-based auth.
11. **2.4** — Cache versioning to prevent stale re-population.
12. Everything else.
