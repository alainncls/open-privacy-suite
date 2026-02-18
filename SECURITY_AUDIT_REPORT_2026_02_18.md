# Security Audit Report: Privacy-Proxy (February 18, 2026)

## Executive Summary

This report details the findings of a security audit performed on the `privacy-proxy` solution. The audit focused on core authentication, authorization (RBAC), middleware security, and data privacy controls. 

Several critical and high-severity vulnerabilities were identified that could lead to unauthorized access to administrative APIs, user impersonation, and partial bypass of privacy controls.

## Vulnerability Summary Table

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [CRIT-01](#crit-01) | Overly Broad IP Range in Localhost Middleware | Critical | New |
| [CRIT-02](#crit-02) | Mock Authentication Bypass (Impersonation) | Critical | New |
| [HIGH-01](#high-01) | Case-Sensitive Method Blocking | High | New |
| [HIGH-02](#high-02) | `X-Forwarded-For` Header Trust Vulnerability | High | New |
| [MED-01](#med-01) | Incomplete Historical State Query Detection | Medium | New |
| [MED-02](#med-02) | ETH Address Re-linking Potential Hijack | Medium | New |

---

## Detailed Findings

<a name="crit-01"></a>
### [CRIT-01] Overly Broad IP Range in Localhost Middleware
**File:** [internal/server/server.go](file:///Users/blade/work/software/privacy-proxy/internal/server/server.go)

**Description:**
The `localhostOnlyMiddleware` intended to protect admin APIs uses simple string prefix checks for IP addresses (e.g., `strings.HasPrefix(clientIP, "172.")`). This is overly broad and dangerous.
- **Attack Vector:** An attacker with an IP like `172.x.y.z` from a different network (e.g., a public VPN or a misconfigured carrier network) would be granted administrative access to the backend if the proxy is exposed.
- **Recommendation:** Implement proper CIDR parsing using `net.IPNet` for specific allowed subnets (e.g., `172.16.0.0/12`).

<a name="crit-02"></a>
### [CRIT-02] Mock Authentication Bypass (Impersonation)
**File:** [internal/server/auth.go](file:///Users/blade/work/software/privacy-proxy/internal/server/auth.go)

**Description:**
The server accepts `mock.` prefixed JWZ tokens to skip ZK proof verification and impersonate any DID. While `config.go` attempts to disable this in production, the logic remains present in the core authentication flow.
- **Attack Vector:** If `ALLOW_MOCK_LOGIN` is accidentally enabled or if an environment variable is leaked/misconfigured, an attacker can impersonate any user DID by providing a token like `mock.did:privado:<TARGET_DID>`.
- **Recommendation:** Remove mock logic from the primary `auth.go` flow or use build tags (`// +build !production`) to ensure it's physically absent from production binaries.

<a name="high-01"></a>
### [HIGH-01] Case-Sensitive Method Blocking
**File:** [internal/rbac/access.go](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go)

**Description:**
The `GlobalBlockedMethods` map uses exact string matches for methods like `debug_traceCall`. 
- **Attack Vector:** Some JSON-RPC nodes or client libraries might handle method names case-insensitively. An attacker might bypass the global blocklist by calling `DEBUG_TRACECALL` or `deBuG_tRaCeCaLl`.
- **Recommendation:** Normalize the method name to lowercase before checking against the `GlobalBlockedMethods` map, and ensure the map keys are all lowercase.

<a name="high-02"></a>
### [HIGH-02] `X-Forwarded-For` Header Trust Vulnerability
**File:** [internal/server/server.go](file:///Users/blade/work/software/privacy-proxy/internal/server/server.go)

**Description:**
The middleware uses `c.ClientIP()`, which relies on `SetTrustedProxies`. If the proxy is deployed behind a load balancer that isn't explicitly trusted, the IP can be spoofed via the `X-Forwarded-For` header.
- **Attack Vector:** An attacker can provide a spoofed `X-Forwarded-For: 127.0.0.1` header to bypass the `localhostOnlyMiddleware`.
- **Recommendation:** Ensure `SetTrustedProxies` is correctly configured in the `init` or `main` function using a known list of upstream proxy IPs.

<a name="med-01"></a>
### [MED-01] Incomplete Historical State Query Detection
**File:** [internal/rbac/access.go](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go)

**Description:**
The `IsHistoricalStateQuery` function only checks `eth_call` and `eth_getStorageAt`. 
- **Severity:** Medium (Privacy Leakage).
- **Vulnerability:** Methods like `eth_getBalance`, `eth_getCode`, and `eth_getTransactionCount` also accept a block parameter. If an attacker queries these for historical blocks, they can reconstruct state history that the proxy is intended to protect.
- **Recommendation:** Expand the method list in `IsHistoricalStateQuery` to include all RPC methods that accept a block parameter.

<a name="med-02"></a>
### [MED-02] ETH Address Re-linking Potential Hijack
**File:** [internal/db/db.go](file:///Users/blade/work/software/privacy-proxy/internal/db/db.go)

**Description:**
The `LinkEthAddress` function uses `ON CONFLICT (eth_address) DO UPDATE` with a `WHERE` clause that limits updates to the *same* DID.
- **Observation:** While this prevents a new DID from hijacking an address *link*, it means that if an admin revokes a link (`revoked = true`), the user cannot re-link it (by design), but the database entry stays "stuck" for that address. There is a potential for address link "denial of service" if an attacker can link an address first.
- **Recommendation:** Ensure that the signature verification (which happens before this DB call) is cryptographically robust and that there's a clear administrative path to resolve address collisions.

---

## Verified Security Controls

Despite the findings, the following controls were verified as effective:
- **Runtime Tracing:** Effectively mitigates custom multicall contract bypasses and `eth_sendRawTransaction` validation gaps.
- **RBAC Enforcement:** The core `CheckAccess` logic correctly identifies and enforces required claims for categorized operations.
- **Travel Rule:** The compliance checker is integrated into the transaction flow (when enabled).
- **Rate Limiting:** Implemented at the processor level and correctly integrated with user/org identities.
