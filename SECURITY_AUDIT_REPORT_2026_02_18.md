# Security Audit Report: Privacy-Proxy (February 18, 2026)

## Executive Summary

This report details the findings of a security audit performed on the `privacy-proxy` solution. The audit focused on core authentication, authorization (RBAC), middleware security, and data privacy controls. 

Several critical and high-severity vulnerabilities were identified that could lead to unauthorized access to administrative APIs, user impersonation, and partial bypass of privacy controls.

## Vulnerability Summary Table

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [CRIT-01](#crit-01) | Overly Broad IP Range in Localhost Middleware | Critical | Fixed |
| [CRIT-02](#crit-02) | Mock Authentication Bypass (Impersonation) | Critical | Fixed |
| [HIGH-01](#high-01) | Case-Sensitive Method Blocking | High | Fixed |
| [HIGH-02](#high-02) | `X-Forwarded-For` Header Trust Vulnerability | High | Fixed |
| [MED-01](#med-01) | Incomplete Historical State Query Detection | Medium | Fixed |
| [MED-02](#med-02) | ETH Address Re-linking Potential Hijack | Medium | Fixed |

---

## Detailed Findings

<a name="crit-01"></a>
### [CRIT-01] Overly Broad IP Range in Localhost Middleware
**File:** [internal/server/server.go](internal/server/server.go)

**Description:**
The `localhostOnlyMiddleware` previously used simple string prefix checks for IP addresses.
- **Attack Vector:** Public IPs like `172.217.x.x` (Google) would have been incorrectly granted administrative access.
- **Remediation:** Switched to strict CIDR matching for RFC1918 and Tailscale ranges (`127.0.0.1/32`, `172.16.0.0/12`, `192.168.0.0/16`, `10.0.0.0/8`, `100.64.0.0/10`).

<a name="crit-02"></a>
### [CRIT-02] Mock Authentication Bypass (Impersonation)
**File:** [internal/server/auth.go](internal/server/auth.go)

**Description:**
The server accepted `mock.` prefixed tokens, bypassing ZK proof verification.
- **Attack Vector:** An attacker could impersonate any user DID by providing a mock token.
- **Remediation:** Moved mock logic to an **opt-in build tag** (`mockauth`). In production builds (default), this logic is physically removed. Added `-tags production` to Dockerfile for defense-in-depth.

<a name="high-01"></a>
### [HIGH-01] Case-Sensitive Method Blocking
**File:** [internal/rbac/access.go](internal/rbac/access.go)

**Description:**
RPC method blocking was previously case-sensitive.
- **Attack Vector:** Bypassing `debug_traceCall` block by calling `DEBUG_TRACECALL`.
- **Remediation:** normalized all RPC method names to lowercase before performing blocklist checks.

<a name="high-02"></a>
### [HIGH-02] `X-Forwarded-For` Header Trust Vulnerability
**File:** [internal/server/server.go](internal/server/server.go)

**Description:**
The middleware relied on `c.ClientIP()` without explicit trusted proxy configuration.
- **Attack Vector:** IP spoofing via `X-Forwarded-For` if deployed behind an untrusted load balancer.
- **Remediation:** Implemented `TRUSTED_PROXIES` configuration and enforced `SetTrustedProxies` for all internal and configured network ranges.

<a name="med-01"></a>
### [MED-01] Incomplete Historical State Query Detection
**File:** [internal/rbac/access.go](internal/rbac/access.go)

**Description:**
Historical state blocking only covered a subset of state-querying methods.
- **Vulnerability:** Privacy leakage via `eth_getBalance`, `eth_getCode`, etc. for historical blocks.
- **Remediation:** Expanded `IsHistoricalStateQuery` to cover all standard methods that accept a block parameter.

<a name="med-02"></a>
### [MED-02] ETH Address Re-linking Potential Hijack
**File:** [internal/db/db.go](internal/db/db.go)

**Description:**
The linking logic had potential edge cases where revoked links could be subverted.
- **Remediation:** Strengthened the `ON CONFLICT` logic in `db.go` to ensure revoked links remain immutable without administrative intervention.

---

## Verified Security Controls
- **Runtime Tracing:** Effectively mitigates custom multicall contract bypasses.
- **RBAC Enforcement:** Core logic identifies and enforces required claims.
- **Rate Limiting:** Integrated with user/org identities.
