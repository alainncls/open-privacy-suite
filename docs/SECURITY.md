# Security Features

## Request Filtering

### Global Method Blocklist

Dangerous JSON-RPC methods are blocked regardless of user permissions:

```
debug_*           - Tracing/debugging (info disclosure, DoS)
admin_*           - Node administration
personal_*        - Account management (key exposure)
miner_*           - Mining control
txpool_*          - Mempool inspection (MEV risk)
clique_*          - Consensus manipulation
les_*             - Light client protocol
eth_sign          - Arbitrary message signing
eth_signTransaction - Transaction signing
```

**Location:** `internal/rbac/access.go`

### Batch Request Prevention

JSON-RPC batch requests (`[{...},{...}]`) are rejected. This prevents:
- Bypassing per-method access control
- Amplification attacks
- Hidden dangerous method calls

**Location:** `internal/proxy/proxy.go`

### Multicall Detection

Calls to Multicall3 contract (`0xcA11bde05977b3631167028862bE2a173976CA11`) are blocked. Multicall allows batching arbitrary contract calls, bypassing method-level restrictions.

**Location:** `internal/rbac/access.go`

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
| Multicall | Only standard address blocked | Monitor for alternate deployments |
