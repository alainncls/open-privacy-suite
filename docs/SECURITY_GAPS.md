# Security Gap Analysis

## Executive Summary

This document identifies security gaps in the Ethereum JSON-RPC privacy proxy implementation. The proxy provides KYC-gated access to an Ethereum node, but several critical security controls are missing that could allow privilege escalation, policy bypass, or resource exhaustion.

**Risk Summary:**
- **Critical**: 2 gaps (Global method blocklist, Batch request handling)
- **High**: 3 gaps (Multicall detection, Contract-level ACL, Rate limiting)
- **Medium**: 3 gaps (Read/write distinction, Request body size limit, Parameter validation)

---

## Gap Analysis

| Gap | Description | Severity | Status |
|-----|-------------|----------|--------|
| **No global method blocklist** | Dangerous methods (debug_*, admin_*, personal_*) can be added to user policies | Critical | Missing |
| **Batch requests unhandled** | JSON-RPC batch `[{...},{...}]` not detected/blocked | Critical | Missing |
| **No Multicall detection** | eth_call to Multicall3 contract bypasses per-method controls | High | Missing |
| **No contract-level ACL** | Only method-level whitelisting, not per-contract | High | Missing |
| **No rate limiting** | No throttling per user/IP/method | High | Missing |
| **No read/write distinction** | All methods treated equally, no read vs write policy | Medium | Missing |
| **No request body size limit** | `io.ReadAll` without limit (Gin default 32MB) | Medium | Missing |
| **No param validation** | Only method name checked, not parameters | Medium | Missing |

---

## Detailed Analysis

### 1. No Global Method Blocklist (Critical)

**Location:** `internal/access/access.go:20-46`

**Current Flow:**
```
CheckAccess(externalID, method)
  -> GetPolicy(externalID)     -- no policy = DENY
  -> Check Banned flag         -- banned = DENY
  -> Check KYC flag            -- no KYC = DENY
  -> Check AllowMethods        -- not in list = DENY
  -> ALLOW
```

**Problem:** There is no global blocklist check before the user whitelist. An administrator could accidentally add dangerous methods like `debug_traceTransaction` or `personal_unlockAccount` to a user's `AllowMethods`, granting them node admin access.

**Methods That Should Be Globally Blocked:**
```
debug_*              - Tracing/debugging (information disclosure, DoS)
admin_*              - Node administration (addPeer, removePeer, etc.)
personal_*           - Account management (key exposure risk)
miner_*              - Mining control
txpool_*             - Mempool inspection (MEV risk)
eth_sign             - Arbitrary message signing
eth_signTransaction  - Transaction signing
eth_sendRawTransaction - May need special handling
```

**Recommendation:** Add a global blocklist check at the start of `CheckAccess()`:
```go
var globalBlockedMethods = []string{
    "debug_", "admin_", "personal_", "miner_", "txpool_",
    "eth_sign", "eth_signTransaction",
}

func (c *Controller) CheckAccess(externalID, method string) error {
    // FIRST: Check global blocklist
    for _, blocked := range globalBlockedMethods {
        if strings.HasPrefix(method, blocked) || method == blocked {
            return fmt.Errorf("method %s is globally blocked", method)
        }
    }
    // ... rest of existing logic
}
```

---

### 2. Batch Requests Unhandled (Critical)

**Location:** `internal/proxy/proxy.go:67-74`

**Current Flow:**
```go
func ParseMethod(body []byte) (string, error) {
    var req JSONRPCRequest
    if err := json.Unmarshal(body, &req); err != nil {
        return "", fmt.Errorf("failed to parse JSON-RPC request: %w", err)
    }
    return req.Method, nil
}
```

**Problem:** JSON-RPC supports batch requests as arrays: `[{"method":"eth_call",...},{"method":"debug_trace",...}]`. The current code only parses single objects, so batch requests will fail parsing but may be forwarded anyway if error handling is inconsistent.

**Exploitation Scenario:**
1. Attacker sends: `[{"method":"eth_call",...},{"method":"admin_addPeer",...}]`
2. `ParseMethod` fails (cannot unmarshal array to struct)
3. Depending on error handling, request may be forwarded to node
4. Node executes all methods in batch

**Recommendation:**
1. Detect batch requests by checking if body starts with `[`
2. Either block batch requests entirely, or parse and validate each method
3. Add explicit batch handling:
```go
func ParseMethod(body []byte) (string, error) {
    body = bytes.TrimSpace(body)
    if len(body) > 0 && body[0] == '[' {
        return "", fmt.Errorf("batch requests not supported")
    }
    // ... existing logic
}
```

---

### 3. No Multicall Detection (High)

**Problem:** The Multicall3 contract (deployed at `0xcA11bde05977b3631167028862bE2a173976CA11` on most networks) allows batching arbitrary contract calls in a single `eth_call`. A user with only `eth_call` permission could use Multicall to invoke any contract, bypassing intended restrictions.

**Exploitation Scenario:**
1. User has `AllowMethods: ["eth_call"]`
2. User calls Multicall3 with targets including sensitive contracts
3. All calls execute under single `eth_call` method

**Recommendation:** Parse `eth_call` parameters and check:
- Target address against allowed contracts
- If target is Multicall3, decode and validate inner calls

---

### 4. No Contract-Level ACL (High)

**Location:** `internal/access/access.go`

**Current State:** Access control is method-level only. User policy contains `AllowMethods []string`.

**Problem:** A user with `eth_call` can call ANY contract. There's no way to restrict users to specific contracts.

**Recommendation:** Extend policy to include contract allowlist:
```go
type AccessPolicy struct {
    ExternalID      string   `json:"external_id"`
    KYC             bool     `json:"kyc"`
    AllowMethods    []string `json:"allow_methods"`
    AllowContracts  []string `json:"allow_contracts"`  // NEW
    Banned          bool     `json:"banned"`
}
```

---

### 5. No Rate Limiting (High)

**Location:** `internal/server/server.go:143`

**Current State:** No rate limiting exists. Every authenticated request is processed immediately.

**Problem:**
- Resource exhaustion via high request volume
- DoS against upstream node
- Cost amplification if node is metered

**Recommendation:** Add rate limiting middleware:
- Per-user rate limit (e.g., 100 req/min)
- Per-IP rate limit (e.g., 1000 req/min)
- Per-method rate limit (expensive methods like `eth_call` lower)
- Global rate limit as safety net

---

### 6. No Read/Write Distinction (Medium)

**Problem:** All methods are treated equally. No distinction between:
- Read methods (eth_call, eth_getBalance) - low risk
- Write methods (eth_sendTransaction) - high risk, may need extra verification

**Recommendation:** Categorize methods and apply different policies:
```go
var readMethods = []string{"eth_call", "eth_getBalance", "eth_blockNumber", ...}
var writeMethods = []string{"eth_sendTransaction", "eth_sendRawTransaction", ...}
```

---

### 7. No Request Body Size Limit (Medium)

**Location:** `internal/server/server.go:175`

**Current Code:**
```go
body, err := io.ReadAll(c.Request.Body)
```

**Problem:** `io.ReadAll` reads the entire body into memory. Gin's default limit is 32MB, but an attacker could send many large requests to exhaust server memory.

**Recommendation:** Use `io.LimitReader`:
```go
const maxBodySize = 1 << 20 // 1MB
body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodySize))
```

---

### 8. No Parameter Validation (Medium)

**Location:** `internal/proxy/proxy.go:67-74`

**Current State:** Only the method name is extracted and checked. Parameters are passed through without validation.

**Problem:**
- Malformed parameters could exploit node vulnerabilities
- Large parameters could cause memory issues
- No validation of address formats, block numbers, etc.

**Recommendation:** Add basic parameter validation:
- Validate parameter count for known methods
- Validate address formats (40 hex chars)
- Validate block number formats (hex or "latest"/"pending")

---

## Implementation Priority

1. **Immediate (Critical):**
   - Add global method blocklist
   - Block/handle batch requests

2. **Short-term (High):**
   - Add rate limiting
   - Implement contract-level ACL
   - Add Multicall detection

3. **Medium-term:**
   - Add request body size limits
   - Implement read/write method distinction
   - Add parameter validation

---

## Code References

| File | Lines | Description |
|------|-------|-------------|
| `internal/access/access.go` | 20-46 | CheckAccess function - add global blocklist here |
| `internal/proxy/proxy.go` | 67-74 | ParseMethod function - add batch detection here |
| `internal/server/server.go` | 143 | JSON-RPC handler - add rate limiting middleware |
| `internal/server/server.go` | 175 | Body reading - add size limit |
