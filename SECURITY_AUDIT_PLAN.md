# Privacy Proxy Security Audit Plan

**Auditor**: White Hat Security Audit
**Date**: 2026-01-30
**Scope**: Full penetration testing of privacy-proxy solution

## Executive Summary

This document outlines a comprehensive security audit plan for the privacy-proxy system. The goal is to identify vulnerabilities that could lead to:
- Unauthorized access to protected data
- Privilege escalation
- Cross-organization data leakage
- Denial of service
- State manipulation

## Attack Surface Analysis

### 1. Authentication Layer
- JWT token issuance and validation
- Privado ZK proof verification
- Mock authentication (development mode)
- Session management

### 2. Authorization Layer (RBAC)
- Method-level permissions
- Contract-level permissions
- Claim enforcement (read/write/admin/deploy/upgrade)
- Cross-org isolation
- Group hierarchy inheritance

### 3. API Endpoints
- Public auth endpoints (rate limited)
- RPC proxy endpoint (JWT protected)
- Admin RBAC endpoints (localhost-only)
- ETH address linking endpoints

### 4. Data Layer
- SQL queries (injection testing)
- Token storage and revocation
- Permission caching

---

## Attack Vectors & Test Cases

### CATEGORY A: Authentication Bypass

#### A1: Mock Token Bypass (CRITICAL)
**Target**: `internal/server/auth.go:399-415`
**Hypothesis**: If `AllowMockLogin` is enabled (non-production), any token starting with "mock." bypasses ZK verification
**Attack**:
```bash
# Try mock tokens to bypass authentication
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer mock.did:example:attacker123" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

#### A2: JWT Token Forgery
**Target**: JWT validation middleware
**Hypothesis**: Test if JWT signature validation can be bypassed
**Attack**: Try malformed JWTs, algorithm confusion, empty signatures

#### A3: Session Hijacking
**Target**: Session ID in URL (`/api/v1/auth/session/:id/status`)
**Hypothesis**: Predictable or enumerable session IDs
**Attack**: Enumerate UUIDs, timing attacks

---

### CATEGORY B: Authorization Bypass

#### B1: Localhost Middleware Bypass (HIGH)
**Target**: `internal/server/server.go:540-544`
**Vulnerability**: IP check uses `strings.HasPrefix(clientIP, "172.")` which matches 172.0.0.0/8 instead of just Docker's 172.16.0.0/12
**Attack**:
```bash
# If attacker controls IP 172.0.0.1 (outside Docker range but matches prefix)
# they could access admin API
curl -X GET http://privacy-proxy:8080/api/v1/rbac/organizations \
  -H "X-Forwarded-For: 172.0.0.1"
```

#### B2: Cross-Org Contract Access (CRITICAL)
**Target**: `internal/rbac/access.go:438-466`
**Hypothesis**: User in Org A can access contracts from Org B via default_claims
**Attack**:
1. Create two orgs with contracts
2. User in Org A tries to read Org B's contracts
3. Check if default_claims allow cross-org access

#### B3: Multicall Bypass
**Target**: `internal/rbac/access.go:187-263`
**Vulnerability**: Only 3 hardcoded Multicall addresses are blocked
**Attack**: Deploy custom Multicall contract at different address and batch unauthorized calls

#### B4: Blocked Method Bypass
**Target**: `GlobalBlockedMethods` map
**Attack**: Try:
- Case variations: `DEBUG_traceTransaction`, `Admin_Peers`
- Unicode homoglyphs: `eth_sign` with lookalike characters
- Prefix/suffix variations: `_debug_traceTransaction`, `debug_traceTransaction_`

#### B5: Historical State Query Bypass
**Target**: `internal/rbac/access.go:903-915`
**Vulnerability**: Only blocks eth_call and eth_getStorageAt
**Attack**: Try historical queries via:
- `eth_getBalance` with block number
- `eth_getCode` with block number
- `eth_getTransactionCount` with block number

---

### CATEGORY C: Privilege Escalation

#### C1: KYC Status Manipulation
**Target**: Admin RBAC API
**Attack**: If admin API is accessible, set KYC=true for any user

#### C2: Group Admin Escalation
**Target**: Group hierarchy
**Attack**: User in child group tries to modify parent group permissions

#### C3: Deploy Claim Escalation
**Target**: Deployment validation
**Attack**:
- Deploy contract that creates other contracts (nested CREATE)
- Deploy contract with dynamic DELEGATECALL
- Deploy CREATE3 factory without admin claim

#### C4: Upgrade Claim Bypass
**Target**: Upgrade validator
**Attack**: Modify proxy implementation without upgrade claim

---

### CATEGORY D: Data Leakage

#### D1: eth_getLogs Without Filter
**Target**: `internal/rbac/access.go:966-968`
**Hypothesis**: Try eth_getLogs without address filter
**Attack**:
```json
{"jsonrpc":"2.0","method":"eth_getLogs","params":[{"topics":["0x..."]}],"id":1}
```

#### D2: Cross-Org Log Access
**Target**: eth_getLogs validation
**Attack**: Include addresses from multiple orgs in same filter

#### D3: Transaction Pool Enumeration
**Target**: Blocked method check
**Attack**: Try `txpool_content` variations

---

### CATEGORY E: Input Validation

#### E1: SQL Injection
**Target**: All database queries
**Attack**: Test org slugs, user IDs, contract addresses:
```
'; DROP TABLE users; --
" OR "1"="1
${7*7}
```

#### E2: JSON-RPC Batch Requests
**Target**: `internal/server/jsonrpc_processor.go`
**Attack**: Try batch requests to bypass per-request validation

#### E3: Oversized Request Body
**Target**: `MaxRequestBodySize` (1MB)
**Attack**: Send requests > 1MB to test DoS resilience

#### E4: Malformed JSON-RPC
**Attack**: Send various malformed payloads:
- Missing jsonrpc version
- Missing method
- Invalid params types
- Negative IDs

---

### CATEGORY F: ETH Address Linking

#### F1: Address Re-linking Attack
**Target**: `internal/db/db.go:339-349`
**Vulnerability**: `ON CONFLICT ... DO UPDATE` allows reassigning addresses
**Attack**:
1. User A links address 0x123
2. User B (attacker) signs challenge with compromised key
3. Address 0x123 now belongs to User B

#### F2: Signature Replay
**Target**: Challenge nonce validation
**Attack**: Reuse challenge nonces across requests

#### F3: Mock Signature Bypass
**Target**: `MOCK_SIGNATURES` config
**Attack**: If enabled, link any address without valid signature

---

### CATEGORY G: Rate Limiting

#### G1: Rate Limit Bypass via Headers
**Attack**: Rotate X-Forwarded-For headers to bypass per-IP limits

#### G2: Auth Endpoint Brute Force
**Target**: `/api/v1/auth/request`
**Attack**: Test rate limit effectiveness

---

### CATEGORY H: CORS & Headers

#### H1: CORS Misconfiguration
**Target**: `corsMiddleware()`
**Vulnerability**: `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
**Attack**: Cross-origin credential theft

---

### CATEGORY I: Contract Deployment Validation

#### I1: Nested CREATE Bypass
**Target**: `DeploymentValidator`
**Attack**: Deploy contract that uses CREATE opcode

#### I2: Dynamic DELEGATECALL Bypass
**Target**: Bytecode analysis
**Attack**: Deploy contract with storage-based DELEGATECALL target

#### I3: Precompile Interaction
**Target**: Allowed precompile list
**Attack**: Try interacting with all precompiles (0x01-0x09)

#### I4: Factory Call Bypass
**Target**: `FactoryCallValidator`
**Attack**: Call CREATE3 factory to deploy to unregistered address

---

## Test Execution Plan

### Phase 1: Setup (Admin API)
1. Create test organizations: OrgA, OrgB
2. Create users: UserA (in OrgA), UserB (in OrgB)
3. Create contracts: ContractA (OrgA), ContractB (OrgB)
4. Configure group permissions

### Phase 2: Authentication Tests (A1-A3)
Execute authentication bypass attempts

### Phase 3: Authorization Tests (B1-B5)
Execute RBAC bypass attempts

### Phase 4: Privilege Escalation Tests (C1-C4)
Attempt to escalate permissions

### Phase 5: Data Leakage Tests (D1-D3)
Attempt to access unauthorized data

### Phase 6: Input Validation Tests (E1-E4)
Test input sanitization

### Phase 7: ETH Linking Tests (F1-F3)
Test address linking vulnerabilities

### Phase 8: Rate Limiting Tests (G1-G2)
Test rate limit effectiveness

### Phase 9: Contract Deployment Tests (I1-I4)
Test deployment validation bypass

---

## Scoring System

| Finding | Severity | Points |
|---------|----------|--------|
| Authentication bypass | Critical | 100 |
| Cross-org data access | Critical | 100 |
| Admin API access | High | 75 |
| Privilege escalation | High | 75 |
| Data leakage | High | 50 |
| Input validation bypass | Medium | 25 |
| Rate limit bypass | Low | 10 |
| Information disclosure | Low | 10 |

---

## Test Files to Create

1. `e2e/playwright/tests/security/auth-bypass.spec.ts`
2. `e2e/playwright/tests/security/cross-org-isolation.spec.ts`
3. `e2e/playwright/tests/security/input-validation.spec.ts`
4. `e2e/playwright/tests/security/localhost-bypass.spec.ts`
5. `e2e/playwright/tests/security/deployment-validation.spec.ts`

---

## Expected Vulnerabilities (Hypothesis)

Based on code review, these are the most likely vulnerabilities:

1. **HIGH**: Localhost middleware IP check is too broad (172.* vs 172.16.0.0/12)
2. **HIGH**: Mock authentication enabled in non-production environments
3. **MEDIUM**: ETH address can be re-linked without explicit revocation
4. **MEDIUM**: Custom Multicall contracts bypass detection
5. **LOW**: Historical state queries not blocked for all methods
