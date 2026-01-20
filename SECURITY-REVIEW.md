# Privacy Proxy Security Review

**Review Date**: January 2025
**Reviewer**: Claude Opus 4.5
**Scope**: OWASP Top 10, crypto-specific, and application-specific security analysis

## Executive Summary

This security review covers correctness and security analysis of the privacy-proxy codebase. The proxy has a solid security foundation with proper JWT handling, parameterized SQL queries, and comprehensive RPC method blocking. However, several high and medium severity issues require attention before production deployment.

---

## Critical & High Severity Findings

### 1. [HIGH] Mock Token Authentication Bypass (CWE-287)

**Location**: `internal/server/auth.go:196-212`

**Issue**: In non-production mode, mock tokens (`mock.*`) bypass Privado ZK verification entirely:
```go
if !s.config.IsProduction() && len(jwzToken) > 5 && jwzToken[:5] == "mock." {
    parts := strings.Split(jwzToken, ".")
    userDID = parts[len(parts)-1]  // DID directly from attacker input
}
```

**Risk**: If `ENVIRONMENT` env var is not correctly set to `"production"`, attackers can forge any user identity with `mock.did:privado:attacker`.

**Recommendation**:
- Add startup validation that `ENVIRONMENT=production` in non-dev deployments
- Consider compile-time flags to completely remove mock token code in release builds
- Log warning if mock token support is enabled

---

### 2. [HIGH] CORS Misconfiguration with Credentials (CWE-942)

**Location**: `internal/server/server.go:120-121`

**Issue**: Wildcard CORS origin combined with credentials:
```go
c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
```

**Risk**: Per spec, browsers ignore this invalid combination, but some edge cases exist. More critically, this indicates the CORS policy wasn't deliberately designed.

**Recommendation**:
- Set explicit allowed origins (frontend URL)
- Use environment variable for allowed origins
- In production, never use `*` with credentials

---

### 3. [HIGH] Admin RBAC API Lacks JWT Authentication (CWE-306)

**Location**: `internal/server/admin_rbac.go:13-56`

**Issue**: All RBAC admin endpoints rely solely on localhost-only middleware:
```go
api.PUT("/users/:user_id", s.updateRBACUser)  // Can modify KYC status
api.POST("/users/:user_id/memberships", s.createUserMembership)
```

**Risk**:
- If localhost detection is bypassed, full RBAC control is exposed
- Docker network ranges (172.*, 192.168.*) are trusted, expanding attack surface

**Recommendation**:
- Add JWT authentication with admin role check as defense-in-depth
- Consider API key authentication for admin endpoints
- Audit Docker network exposure

---

## Medium Severity Findings

### 4. [MEDIUM] Missing Rate Limiting on Auth Endpoints (CWE-307)

**Location**: `internal/server/server.go:145-156`

**Issue**: Auth endpoints have no rate limiting:
- `POST /auth/request`
- `POST /auth/callback`
- `POST /refresh`
- `POST /revoke`

**Risk**: Enables brute-force attacks on token refresh, DoS via auth request flooding.

**Recommendation**: Apply rate limiting (stricter than RPC limits) to auth endpoints.

---

### 5. [MEDIUM] Localhost Detection Uses String Prefix (CWE-290)

**Location**: `internal/server/server.go:333-336`

**Issue**:
```go
strings.HasPrefix(clientIP, "172.") ||  // Too broad
strings.HasPrefix(clientIP, "192.168.")
```

**Risk**: `172.*` matches `172.0-255.*`, not just Docker's `172.16.0.0/12`. Allows `172.0.0.1` through `172.15.255.255` which aren't Docker ranges.

**Recommendation**: Use proper CIDR matching via `net.ParseIP()` and range checks.

---

### 6. [MEDIUM] JWT Secrets Auto-Generated in Development (CWE-321)

**Location**: `internal/auth/jwt.go:47-72`, `internal/config/config.go:39-40`

**Issue**: Empty JWT secrets trigger auto-generation:
```go
JWTSecret: getEnv("JWT_SECRET", "")  // Empty default
```

**Risk**:
- Tokens invalid after restart (new random secret)
- If deployed with defaults, sessions unpredictable

**Recommendation**:
- Fail startup if secrets not configured in production
- Add explicit validation in `config.Load()`

---

### 7. [MEDIUM] ETH Address Re-linking Without Revocation (CWE-284)

**Location**: `internal/db/db.go` (via `ON CONFLICT(eth_address) DO UPDATE`)

**Issue**: ETH addresses can be re-linked to different DIDs without explicit revocation.

**Risk**: Address reassignment could enable impersonation if an address is stolen or compromised.

**Recommendation**: Require explicit unlinking before re-linking, or maintain link history.

---

### 8. [MEDIUM] In-Memory Session Storage (CWE-384)

**Location**: `internal/server/auth.go:58`

**Issue**: Auth sessions stored in memory only, lost on restart.

**Risk**:
- Auth flows interrupted by restart
- Horizontal scaling impossible without session sharing

**Recommendation**: Use Redis or database-backed session storage.

---

### 9. [MEDIUM] No HTTP Client Timeouts for Proxy (CWE-400)

**Location**: `internal/proxy/proxy.go:20`

**Issue**:
```go
client: &http.Client{},  // Uses default timeouts
```

**Risk**: Slow upstream nodes can exhaust connections, enabling DoS.

**Recommendation**: Set explicit `Timeout`, `DialContext` timeouts.

---

## Low Severity Findings

### 10. [LOW] Arbitrary Metadata JSON (CWE-20)

**Location**: `internal/server/admin_rbac.go` user update handler

**Issue**: User metadata accepts arbitrary JSON without schema validation.

**Risk**: Could store unexpected data types, XSS payloads if rendered in frontend.

**Recommendation**: Define allowed metadata schema, sanitize on input.

---

### 11. [LOW] Multicall Detection Limited to Known Addresses (CWE-184)

**Location**: `internal/rbac/access.go:172-176`

**Issue**: Hardcoded Multicall contract addresses:
```go
var MulticallAddresses = map[string]bool{
    "0xca11bde05977b3631167028862be2a173976ca11": true,  // Multicall3
    // ...
}
```

**Risk**: New Multicall deployments at different addresses bypass detection.

**Recommendation**:
- Add configuration for custom Multicall addresses
- Consider detecting by function selector regardless of address

---

### 12. [LOW] Type Assertion Failures Silent (CWE-754)

**Location**: `internal/rbac/access.go:215-222`

**Issue**: Type assertions in param parsing fail silently:
```go
callObj, ok := params[0].(map[string]any)
if !ok {
    return false, ""  // Silent failure
}
```

**Risk**: Malformed requests may bypass Multicall detection without logging.

**Recommendation**: Log failed assertions for security monitoring.

---

## OWASP Top 10 Coverage

| Category | Status | Notes |
|----------|--------|-------|
| A01 Broken Access Control | ISSUES | Mock token bypass, admin API auth |
| A02 Cryptographic Failures | Good | Proper EIP-191, SHA256 token hashing |
| A03 Injection | Good | All SQL parameterized |
| A04 Insecure Design | Minor | Session storage, CORS config |
| A05 Security Misconfiguration | ISSUES | CORS, localhost detection |
| A06 Vulnerable Components | Good | Standard Go/Ethereum libs |
| A07 Auth Failures | ISSUES | No rate limit on auth endpoints |
| A08 Data Integrity | Good | JWT signatures, ZK verification |
| A09 Logging/Monitoring | Good | Access logging present |
| A10 SSRF | Good | Node URL from config only |

---

## Crypto-Specific Findings

### Positive Findings

1. **EIP-191 Signature Verification** (`internal/auth/eth_signature.go:39-41`)
   - Correct use of `accounts.TextHash()` for personal_sign
   - Proper V value normalization (lines 60-64)
   - Validates address format before comparison

2. **ZK Proof Verification** (`internal/auth/privado.go`)
   - Uses Privado library's `FullVerify()` (line 113)
   - Validates verifier ID matches (lines 122-127)
   - KYC claims enforced at access check (lines 299-305)

3. **RPC Method Blocklist** (`internal/rbac/access.go:15-143`)
   - Comprehensive blocking of dangerous namespaces:
     - `debug_*` (27 methods) - info disclosure/DoS
     - `admin_*` (18 methods) - node control
     - `personal_*` (14 methods) - key exposure
     - `miner_*` (8 methods) - MEV risk
     - `txpool_*` (4 methods) - MEV/info disclosure
     - `eth_sign*` - signing key exposure
     - `clique_*` - consensus manipulation
     - `les_*` - light client control
   - Also blocks by prefix for future-proofing

4. **Multicall Detection** (`internal/rbac/access.go:188-241`)
   - Detects known Multicall contracts (v1, v2, v3)
   - Checks function selectors
   - Prevents ACL bypass via batch calls

### Crypto Concerns

1. **Contract Address Comparison** (`internal/rbac/access.go`)
   - Uses lowercase comparison but should validate checksum for EIP-55

2. **Multicall Coverage Gaps**
   - Only known Multicall addresses blocked
   - New deployments or custom batching contracts could bypass

---

## Application-Specific Findings

### Positive Architecture Decisions

1. **Defense in Depth**: JWT -> RBAC -> Rate Limiting pipeline
2. **Batch Request Blocking**: Prevents enumeration attacks
3. **1MB Request Size Limit**: DoS protection
4. **Token Rotation**: Old refresh tokens revoked on issuance
5. **Token Hashing**: Refresh tokens stored as SHA256 hashes
6. **Trusted Proxy Configuration**: X-Forwarded-For spoofing prevented

### Areas for Improvement

1. **Session Management**: Move from in-memory to persistent storage
2. **Admin API**: Add authentication layer beyond localhost
3. **Configuration Validation**: Fail fast on missing secrets
4. **Rate Limiting**: Extend to auth endpoints

---

## Summary of Recommendations

### Immediate (Before Production)
1. Ensure `ENVIRONMENT=production` is set and validated on startup
2. Fix CORS to use explicit origins instead of wildcard
3. Add rate limiting to auth endpoints

### Short-term
4. Add JWT auth to admin RBAC API as defense-in-depth
5. Fix localhost IP detection to use proper CIDR parsing
6. Add startup validation for required secrets (JWT_SECRET, JWT_REFRESH_SECRET)

### Medium-term
7. Implement persistent session storage (Redis/database)
8. Add configurable Multicall addresses
9. Set explicit HTTP client timeouts
10. Add security logging for failed type assertions

---

## Files Reviewed

| File | Security Relevance |
|------|-------------------|
| `internal/server/auth.go` | Auth flow, mock token bypass |
| `internal/server/server.go` | CORS, routing, middleware |
| `internal/server/admin_rbac.go` | Admin API endpoints |
| `internal/server/eth_link.go` | ETH address linking |
| `internal/server/ratelimit.go` | Rate limiting implementation |
| `internal/rbac/access.go` | Access control, method blocking |
| `internal/rbac/resolver.go` | Permission resolution |
| `internal/rbac/cache.go` | Permission caching |
| `internal/auth/jwt.go` | Token issuance/validation |
| `internal/auth/eth_signature.go` | ETH signature verification |
| `internal/auth/privado.go` | ZK proof verification |
| `internal/auth/zk_roles.go` | ZK role extraction |
| `internal/config/config.go` | Configuration loading |
| `internal/db/db.go` | Database operations |
| `internal/db/rbac_store.go` | RBAC database operations |
| `internal/proxy/proxy.go` | RPC proxying |
