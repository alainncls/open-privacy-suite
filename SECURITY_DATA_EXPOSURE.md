# Security Audit: Data Exposure Vulnerabilities

**Audit Date**: 2026-02-02
**Scope**: API data exposure, cross-org isolation, sensitive data disclosure
**Status**: FINDINGS CATEGORIZED BY ACCESS LEVEL

---

## Important Note: Admin vs User Endpoints

This report separates findings into two categories:

1. **Admin API Issues** (`/api/v1/*` with localhost-only middleware)
   - These endpoints are intentionally accessible only from localhost/Docker/Tailscale
   - They are designed for admin access and don't require per-user auth
   - Issues here are "known limitations" of the network-based security model

2. **User-Facing Issues** (JWT-protected, externally accessible)
   - These endpoints require valid JWT authentication
   - Issues here affect regular users and need immediate attention

---

## Executive Summary

The admin API (`/api/v1/*`) is protected only by localhost/network checks with **ZERO application-level authentication or authorization**. Any client that can reach the API (localhost, Docker network, Tailscale) has **FULL READ AND WRITE ACCESS** to all data across all organizations.

### Admin API Findings (Localhost-Only)

| # | Severity | Finding | Impact |
|---|----------|---------|--------|
| 1 | CRITICAL | Full admin API accessible without auth | Complete system compromise |
| 2 | CRITICAL | CREATE3 salts exposed | Contract deployment front-running |
| 3 | CRITICAL | User DIDs (external_id) exposed | Identity/PII disclosure |
| 4 | CRITICAL | No cross-org isolation | Multi-tenant data breach |
| 5 | HIGH | KYC status exposed | Regulatory compliance violation |
| 6 | HIGH | Can create/delete any resource | Data integrity destruction |
| 7 | HIGH | Audit logs cross-org accessible | Activity pattern disclosure |
| 8 | MEDIUM | Sessions enumerable | Auth timing attacks |
| 9 | MEDIUM | Effective permissions queryable | Security posture disclosure |

**Note**: These admin API issues require localhost/Docker/Tailscale network access.

### User-Facing Findings (External Access with JWT)

| # | Severity | Finding | Impact |
|---|----------|---------|--------|
| U1 | LOW | RPC error reveals cross-org contract ownership | Information disclosure |
| U2 | LOW | Token format revealed in refresh errors | Token structure disclosure |
| U3 | LOW | Internal IP in auth callback URL | Network topology disclosure |

**Note**: User-facing endpoints are properly secured with JWT authentication and ownership verification.

---

## CRITICAL-001: Admin API Has No Authentication

**Location**: All `/api/v1/*` endpoints
**Severity**: CRITICAL

### Description

The entire admin API relies solely on `localhostOnlyMiddleware` for access control. There is no JWT validation, API key check, or any authentication mechanism.

### Proof of Concept

```bash
# Create an organization - NO AUTH REQUIRED
curl -X POST http://localhost:8080/api/v1/orgs \
  -H "Content-Type: application/json" \
  -d '{"slug": "attacker-org", "name": "Attacker Org"}'

# Response: {"id": "xxx", "slug": "attacker-org", ...}
# ORGANIZATION CREATED!
```

### Impact

Anyone with network access can:
- Create/delete organizations
- Create/delete users, groups, contracts
- Ban users, modify KYC status
- Access all data from all organizations

---

## CRITICAL-002: CREATE3 Deployment Salts Exposed

**Location**: `GET /api/v1/orgs/:org_id/addresses/preregistered`
**Severity**: CRITICAL

### Description

Preregistered CREATE3 addresses include the **salt** used for deterministic deployment. This is a cryptographic secret that determines the deployed contract address.

### Proof of Concept

```bash
curl http://localhost:8080/api/v1/orgs/a0ee45c2-8eec-4b49-a930-6f0fcb60f597/addresses/preregistered | jq '.[0]'
```

Response:
```json
{
  "id": "d54aed95-1acd-4a18-bfa8-8efd166d6423",
  "address": "0x825561259ab5cc84902bc1ed9d00171a4a574a36",
  "factory": "0x2279b7a0a67db372996a5fab50d91eaa73d2ebe6",
  "salt": "0x0b7f4579f0976dbe7d7470ac3ecc1ac4834ca32a405a984b9184931c64bcfc1d",
  "note": "Final test"
}
```

### Impact

An attacker who obtains the salt can:
1. Calculate the exact address where a contract will be deployed
2. Deploy a malicious contract to that address BEFORE the legitimate deployment
3. Steal funds or hijack contract functionality (front-running attack)

### Remediation

**NEVER expose salts**. Return only:
```json
{
  "address": "0x825561259ab5cc84902bc1ed9d00171a4a574a36",
  "note": "Final test",
  "created_at": "2026-01-30T16:28:38Z"
}
```

---

## CRITICAL-003: User DIDs (Decentralized Identifiers) Exposed

**Location**: `GET /api/v1/users`, `GET /api/v1/users/:id`
**Severity**: CRITICAL

### Description

User responses include `external_id` which is the user's DID (Decentralized Identifier). DIDs are persistent identity credentials that can be used to:
- Track users across systems
- Link on-chain activity to real identities
- Correlate with other databases

### Proof of Concept

```bash
curl http://localhost:8080/api/v1/users | jq '.[0]'
```

Response:
```json
{
  "id": "ac841c6f-8a97-48fe-971a-3d11da88355f",
  "external_id": "did:demo:deployer-1770028069",  // PII!
  "kyc": true,
  "banned": false,
  "metadata": {}
}
```

### Impact

- **Privacy violation**: DIDs are identity credentials
- **Cross-system correlation**: Attackers can link users across platforms
- **Regulatory risk**: May violate GDPR, CCPA for exposing identifiers

### Exposed Data per User

| Field | Sensitivity | Exposed |
|-------|-------------|---------|
| id | Low | Yes |
| external_id (DID) | **CRITICAL** | Yes |
| kyc | **HIGH** | Yes |
| banned | Medium | Yes |
| note | Medium | Yes |
| metadata | Varies | Yes |

---

## CRITICAL-004: No Cross-Organization Isolation

**Location**: All org-scoped endpoints
**Severity**: CRITICAL

### Description

There is no validation that the requesting user belongs to the organization they're querying. Any authenticated localhost client can access ANY organization's data.

### Proof of Concept

```bash
# List ALL organizations
curl http://localhost:8080/api/v1/orgs
# Returns: [{"id": "default-org"}, {"id": "gw-llc"}, ...]

# Access GW LLC's contracts (we're not a member)
curl http://localhost:8080/api/v1/orgs/a0ee45c2-8eec-4b49-a930-6f0fcb60f597/contracts
# Returns: All contracts

# Access GW LLC's groups
curl http://localhost:8080/api/v1/orgs/a0ee45c2-8eec-4b49-a930-6f0fcb60f597/groups
# Returns: All groups with is_org_admin flags

# Access GW LLC's preregistered addresses
curl http://localhost:8080/api/v1/orgs/a0ee45c2-8eec-4b49-a930-6f0fcb60f597/addresses/preregistered
# Returns: 53 preregistered addresses with salts
```

### Impact

Complete breakdown of multi-tenant isolation. Organization A can read/write all data from Organization B.

---

## HIGH-001: KYC Status Disclosure

**Location**: `GET /api/v1/users/:id`
**Severity**: HIGH

### Description

KYC (Know Your Customer) status is sensitive financial/regulatory data indicating whether a user has completed identity verification.

### Impact

- Regulatory compliance violation (KYC data is protected)
- Can be used to identify high-value targets (KYC = verified identity = real person)
- May indicate financial status or business relationship

---

## HIGH-002: Full Write Access Without Auth

**Location**: All POST/PUT/DELETE endpoints
**Severity**: HIGH

### Confirmed Write Operations

| Endpoint | Method | Impact |
|----------|--------|--------|
| `/api/v1/orgs` | POST | Create organizations |
| `/api/v1/orgs/:id` | DELETE | Delete organizations |
| `/api/v1/orgs/:id/groups` | POST | Create groups |
| `/api/v1/orgs/:id/contracts` | POST | Register contracts |
| `/api/v1/users/:id` | PUT | Ban users, modify KYC |
| `/api/v1/users/:id/memberships` | POST/DELETE | Add/remove permissions |

### Proof of Concept

```bash
# Ban a user
curl -X PUT http://localhost:8080/api/v1/users/{user_id} \
  -H "Content-Type: application/json" \
  -d '{"banned": true, "note": "Banned by attacker"}'
```

---

## HIGH-003: Audit Logs Cross-Org Accessible

**Location**: `GET /api/v1/audit-logs`
**Severity**: HIGH

### Description

Audit logs are queryable across all organizations, revealing:
- Who created/modified resources
- When changes occurred
- Resource IDs that can be used for further enumeration

### Proof of Concept

```bash
curl "http://localhost:8080/api/v1/audit-logs?resource_type=user&limit=100"
```

Returns all user creation/modification events across all orgs.

---

## MEDIUM-001: Sessions Enumerable

**Location**: `GET /api/v1/sessions`
**Severity**: MEDIUM

### Description

Active authentication sessions are listable, showing:
- Session IDs
- Creation/expiry times
- Completion status

### Impact

- Timing analysis of authentication patterns
- Session hijacking if session tokens are predictable

---

## MEDIUM-002: Effective Permissions Queryable

**Location**: `GET /api/v1/users/:id/effective-permissions`
**Severity**: MEDIUM

### Description

Can query any user's computed permissions including:
- Allowed RPC methods
- Default claims (read/write/admin)
- Rate limits

### Impact

Reveals security posture and capabilities of any user.

---

## Summary of Exposed Data

### Quantified Exposure (Current Database)

| Data Type | Count | Sensitivity |
|-----------|-------|-------------|
| Organizations | 3 | Medium |
| Users with DIDs | 18 | **CRITICAL** |
| Preregistered addresses with salts | 53 | **CRITICAL** |
| Groups with admin flags | 4 | Medium |
| Active sessions | 2 | Medium |
| Audit log entries | 18+ | Medium |

---

## Remediation Priorities

### Immediate (P0 - This Week)

1. **Add authentication to admin API**
   - Require JWT or API key on all `/api/v1/*` endpoints
   - Implement proper session validation

2. **Remove salts from preregistered address responses**
   - Salt is a deployment secret, never expose externally

3. **Redact sensitive user fields**
   - Never return `external_id` (DID) to non-admin users
   - Create separate admin/user response DTOs

### High Priority (P1 - This Month)

4. **Implement cross-org authorization**
   - Extract org_id from authenticated user
   - Validate all org-scoped operations

5. **Add field-level access control**
   - KYC status only visible to org admins
   - Metadata restricted based on permissions

### Medium Priority (P2)

6. **Audit log filtering by org**
7. **Session visibility restrictions**
8. **Rate limiting on enumeration endpoints**

---

## USER-FACING (Non-Admin) Security Issues

These issues affect the JWT-protected endpoints that are accessible from external IPs.

### USER-001: Information Disclosure via RPC Error Messages (LOW)

**Location**: `/rpc` endpoint error responses
**Severity**: LOW
**Externally Accessible**: YES (with valid JWT)

#### Description

When a user attempts to access a contract registered to another organization, the error message reveals this fact:

```
"access denied: contract 0x1234... is registered to another organization"
```

#### Impact

- Confirms that a contract is tracked by the system
- Reveals cross-org boundaries (but not WHICH org)
- Could aid in mapping the system's contract registry

#### Recommendation

Use generic error: "access denied: no permission for contract 0x1234..."

---

### USER-002: Token Format Disclosure via Refresh Errors (LOW)

**Location**: `POST /api/v1/refresh`
**Severity**: LOW
**Externally Accessible**: YES

#### Description

Refresh token errors reveal internal token structure:
- "token is malformed: could not base64 decode header"
- "token signature is invalid"
- "token contains an invalid number of segments"

#### Impact

- Reveals JWT/token structure details
- Could help attackers craft better attack payloads
- Low risk since JWT format is well-documented

#### Recommendation

Use generic error: "invalid refresh token"

---

### USER-003: Internal IP in Auth Callback URL (LOW)

**Location**: `POST /api/v1/auth/request` response
**Severity**: LOW
**Externally Accessible**: YES

#### Description

The auth request response includes internal network IP in callback URL:
```json
{
  "callbackUrl": "192.168.1.133:5173/auth/callback?session=..."
}
```

#### Impact

- Reveals internal network topology
- Could aid reconnaissance for further attacks

#### Recommendation

Use public hostname or configure callback URL properly.

---

### USER-VERIFIED: Security Controls Working Correctly

The following user-facing security controls were tested and confirmed working:

| Control | Status | Notes |
|---------|--------|-------|
| JWT required for RPC | ✅ PASS | Returns "missing Authorization header" |
| JWT required for ETH linking | ✅ PASS | Properly requires authentication |
| Session enumeration protection | ✅ PASS | Same error for missing/expired sessions |
| ETH address ownership verification | ✅ PASS | Can only see/modify own addresses |
| Disclosure request ownership | ✅ PASS | Can only approve/reject own requests |
| Challenge-response for ETH linking | ✅ PASS | Nonce tied to user's DID |
| Introspect endpoint | ✅ PASS | Returns `active: false` for invalid tokens |

---

## Conclusion

The privacy-proxy admin API has **CRITICAL data exposure vulnerabilities** due to the complete absence of application-level authentication and authorization. The reliance on network-level security (localhost checks) provides no protection against:

- Compromised admin machines
- Docker container escapes
- Tailscale network breaches
- Insider threats

**All sensitive data across all organizations is accessible to any client that can reach the API.**

---

*Report generated 2026-02-02*
