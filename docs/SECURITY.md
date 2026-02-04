# Security Features

## Request Filtering

### Global Method Blocklist

Dangerous JSON-RPC methods are blocked regardless of user permissions:

```
debug_*              - Tracing/debugging (info disclosure, DoS)
admin_*              - Node administration
personal_*           - Account management (key exposure)
miner_*              - Mining control
txpool_*             - Mempool inspection (MEV risk)
clique_*             - Consensus manipulation
les_*                - Light client protocol
eth_sign             - Arbitrary message signing
eth_signTransaction  - Transaction signing
eth_sendRawTransaction - Pre-signed transactions (bypasses ALL validation)
eth_subscribe        - WebSocket subscriptions (bypasses filtering)
eth_unsubscribe      - WebSocket subscriptions
```

**Note on eth_sendRawTransaction:** This method is **always blocked** because raw transactions are pre-signed and cannot be inspected for RBAC validation. The proxy cannot determine the sender, target contract, or method being called without RLP decoding the signed transaction, which would bypass all security controls.

**Location:** `internal/rbac/access.go`

### Batch Request Prevention

JSON-RPC batch requests (`[{...},{...}]`) are rejected. This prevents:
- Bypassing per-method access control
- Amplification attacks
- Hidden dangerous method calls

**Location:** `internal/proxy/proxy.go`

### Multicall Detection

Calls to known Multicall contracts are blocked:
- Multicall3: `0xcA11bde05977b3631167028862bE2a173976CA11`
- Multicall2: `0x5ba1e12693dc8f9c48aad8770482f4739beed696`
- Multicall1: `0xeefba1e63905ef1d7acba5a8513c70307c1ce441`

Multicall allows batching arbitrary contract calls, bypassing method-level restrictions.

**Location:** `internal/rbac/access.go`

### Contract Deployment Protection

Contract deployments require the `deploy` claim:

| Method | Deployment Detection | Validation |
|--------|---------------------|------------|
| `eth_sendTransaction` | Missing/empty/null `to` field | Requires `deploy` claim |
| `eth_estimateGas` | Missing/empty/null `to` field | Requires `deploy` claim |

**Bytecode validation** is performed on deployments:
- No CREATE/CREATE2 opcodes (prevents nested deployments)
- All static CALL targets must be org-owned or precompiles

When `ENABLE_RUNTIME_TRACING=true` (default), dynamic calls are **allowed** at deployment because they are validated at runtime via transaction tracing.

**CREATE3 factory deployments** additionally require the `admin` claim.

### Runtime Transaction Validation

When `ENABLE_RUNTIME_TRACING=true`, every transaction is traced using `debug_traceCall` before being forwarded to the node:

```
Transaction → debug_traceCall → Extract all CALL/DELEGATECALL/STATICCALL targets
                                      ↓
                              Validate each target:
                              ├── Org-owned? → Allowed
                              ├── Precompile (0x01-0x09)? → Allowed
                              ├── Shared infrastructure? → Allowed
                              ├── Other org's contract? → DENIED
                              └── CREATE/CREATE2 detected? → DENIED
```

**Benefits of runtime tracing:**
- Catches **all** internal calls, including from custom multicall contracts
- Validates dynamic DELEGATECALL targets that can't be known at deployment
- Provides comprehensive cross-org isolation
- Defense-in-depth with bytecode validation

**Performance:** ~50-200ms additional latency per transaction. Tiered validation skips tracing for calls to known org-owned addresses.

### Cross-Organization Isolation

The RBAC system enforces strict isolation between organizations:

**Organization Context Resolution:**
When a user accesses a contract:
1. System looks up which organization owns the target contract
2. Verifies user has membership in that organization
3. Uses that organization's permission context for access checks

**Isolation Rules:**
- Users can only access contracts owned by organizations they belong to
- `default_claims` only apply to **public contracts** (not registered to any org)
- Contract registered to Org A cannot be accessed by Org B users via default_claims

**Multi-Organization Users:**
Users can be members of multiple organizations. The system:
1. Determines org context from target contract ownership
2. Loads permissions from the correct organization
3. Rejects requests where target contract belongs to an org the user isn't a member of

**eth_getLogs Cross-Org Protection:**
- All addresses in filter are validated
- Mixed-org address filters are rejected
- Requests without address filter are rejected

### Request Size Limit

Request bodies are limited to 1MB to prevent memory exhaustion.

**Location:** `internal/server/server.go`

---

## Authentication Security

### ZK-Proof Verification

- Privado ID JWZ tokens cryptographically verified
- Proofs bound to specific authorization requests
- Cannot be replayed to other verifiers
- Session TTL prevents stale proofs

### JWT Token Security

| Feature | Implementation |
|---------|----------------|
| Signing | HS256 with strong secrets |
| Access TTL | 30 minutes |
| Refresh TTL | 7 days |
| Token rotation | Refresh tokens rotated on use |
| Revocation | Blacklist stored in database |

### ETH Address Linking

- One-time nonce challenges (5 min TTL)
- EIP-191 signature verification
- Challenge bound to user's DID
- Nonce consumed on verification

---

## Authorization Security

### RBAC Model

- **Restrictive inheritance**: Child groups can only narrow permissions
- **Multi-membership**: Union of permissions across memberships
- **Expiring memberships**: Optional expiration timestamps
- **Immutable audit log**: All changes tracked

### Access Control Flow

```
1. Validate JWT (signature, expiry, revocation)
2. Check global method blocklist
3. Check Multicall contract
4. Load user (verify exists, not banned, has KYC)
5. Resolve effective permissions (cached)
6. Check method in allowlist
7. Check contract in allowlist (if applicable)
8. Check rate limits
9. Forward request
```

### Rate Limiting

- Per-user sliding window (RPS)
- Per-user daily counter
- Limits configurable per group
- Returns 429 when exceeded

---

## API Security

### Admin API Protection

All `/api/*` endpoints restricted to localhost only. In Docker, this includes container network (`172.16.0.0/12`).

### Trusted Proxies

`X-Forwarded-For` headers only trusted from:
- `127.0.0.1`
- `172.16.0.0/12` (Docker networks)

### CORS

Configured via Gin middleware. Adjust in `internal/server/server.go` for production.

---

## Production Checklist

- [ ] Set strong, unique `JWT_SECRET` and `JWT_REFRESH_SECRET`
- [ ] Set `ENVIRONMENT=production`
- [ ] Configure `VERIFIER_ID` with your Privado DID
- [ ] Set `BASE_URL` to public HTTPS URL
- [ ] Enable `REQUIRE_PROOF_OF_HUMANITY` if using Billions
- [ ] Configure PostgreSQL with SSL (`sslmode=require`)
- [ ] Place behind reverse proxy with TLS termination
- [ ] Restrict admin API access at network level
- [ ] Set up log aggregation for audit trail
- [ ] Configure rate limits appropriate for your use case

---

## Known Limitations

| Area | Limitation | Mitigation |
|------|------------|------------|
| Parameter validation | Only method/contract validated | Upstream node validation |
| Token revocation | Database lookup per request | Consider Redis for high volume |
| Multicall | Only 3 hardcoded addresses blocked | Mitigated by runtime tracing (all calls validated regardless of target) |
| Method case sensitivity | Methods checked case-sensitively | Ethereum nodes typically reject wrong case |
| Localhost IP ranges | 172.x prefix check is overly broad | See SECURITY_FINDINGS.md for fix |
| Historical state | Only eth_call/eth_getStorageAt blocked | Other methods (eth_getBalance) accept historical blocks |

## Security Audit

See `SECURITY_FINDINGS.md` for detailed vulnerability analysis and remediation recommendations.
