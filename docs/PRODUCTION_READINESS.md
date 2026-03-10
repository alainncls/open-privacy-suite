# Production Readiness Assessment

Last updated: 2026-03-10 | Branch: `feat/prometheus-metrics`

## Overall Status: Ready for MVP

Infrastructure, security, deployment, and auth systems are solid. One significant gap remains in the KYC flow (see below).

---

## 1. KYC / Billions Credentials — Current State

### How Authentication Works Today

1. User scans QR code with Privado wallet
2. Wallet generates a ZK proof of a `ProofOfHumanity` credential from Billions
3. Backend verifies the proof via `go-iden3-auth` (real cryptographic verification — signatures, state commitment, revocation check)
4. If proof is valid, user gets `kyc=false` in the database and a JWT is issued
5. **Admin manually sets `kyc=true`** via admin API/dashboard

### The Gap

Step 5 is the problem. The ZK proof verifies that the user *has* the Billions `ProofOfHumanity` credential, but the `kyc` boolean is **not set automatically from the proof result**. It requires manual admin intervention.

Without the auto-set, every user needs manual admin approval — this does not scale for production.

**Recommended fix:** When `ProofOfHumanity` verification succeeds in the auth callback, auto-set `kyc=true` on the user record. The credential IS the KYC; no manual step should be needed.

### What's Hardcoded in Credential Verification

| Value | Location | Configurable? |
|-------|----------|---------------|
| Issuer DID | `BILLIONS_ISSUER_DID` env var | Yes |
| PoH toggle | `REQUIRE_PROOF_OF_HUMANITY` env var | Yes |
| Verifier ID | `VERIFIER_ID` env var | Yes |
| Privado RPC | `PRIVADO_RPC_URL` env var | Yes |
| IPFS Gateway | `IPFS_GATEWAY` env var | Yes |
| Circuit type (`credentialAtomicQueryMTPV2`) | `internal/auth/privado.go:82` | No — hardcoded |
| Credential field (`isHuman == 1`) | `internal/auth/privado.go:86-88` | No — hardcoded |
| Schema URL (PolygonID tutorial examples) | `internal/auth/privado.go:90` | No — hardcoded |
| Credential type (`ProofOfHumanity`) | `internal/auth/privado.go:91` | No — hardcoded |
| State contract address | `internal/auth/privado.go:24` | No — hardcoded |

### Action Required Before Go-Live

- **Verify Billions schema:** Confirm the hardcoded schema URL (`https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/.../proof-of-humanity.jsonld`) matches what Billions actually issues. If they use a different schema/context, proof verification will fail.
- **Set `BILLIONS_ISSUER_DID`** to the actual Billions issuer DID.
- **Test the full flow** with a real Privado wallet and a real Billions-issued credential.

---

## 2. Security Hardening (Completed)

The following security issues were identified via audit and fixed on the branch:

### C1. Removed `VITE_ADMIN_API_TOKEN` from Build Pipeline (Critical)

Vite bakes `VITE_*` env vars into the static JS bundle — the admin M2M token would have been visible to every browser visitor.

- Removed from `frontend/Dockerfile` build args
- Removed from `docker-compose.yml`
- Frontend `adminClient.ts` no longer reads from `import.meta.env`
- Browser-based admin access uses JWT auth; bootstrap uses `curl` with `X-Admin-Token` directly against the backend

### C2. Made `auth_tenant_id` Immutable at DB Level (Critical)

`UpdateUser()` could overwrite `auth_tenant_id`, enabling cross-tenant reassignment.

- `UpdateUser()` no longer writes `auth_tenant_id`
- New `SetAuthTenantID()` only succeeds when the column is `NULL` (single atomic SQL statement)
- Azure callback paths updated to use the new method

### H1. Added Security Headers to Nginx (High)

Both `nginx.prod.conf` and `nginx.e2e.conf` now include:
- `X-Frame-Options: DENY` (clickjacking)
- `X-Content-Type-Options: nosniff` (MIME sniffing)
- `Content-Security-Policy` (XSS mitigation, self-only, frame-ancestors none)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` (camera, microphone, geolocation, payment disabled)

### M1. Startup Warning for Empty Admin Token (Medium)

Logs `WARNING: ADMIN_API_TOKEN is not set...` in dev mode. In production, the server refuses to start without it (enforced by `config.Validate()`).

### Accepted Risks (Documented, Not Fixed)

| Issue | Severity | Rationale |
|-------|----------|-----------|
| JWTs in localStorage | High | Standard SPA trade-off. Mitigated by CSP headers. httpOnly cookies require auth architecture change. |
| `/me/admin-status` externally accessible | High | By design — frontend needs it. Read-only, JWT-protected, returns only a boolean. |
| No PKCE on Azure OAuth | Medium | Backend uses client secret. PKCE is for public clients. |
| No rate limiting on admin endpoints | Medium | Protected by network isolation + token auth. |
| Wide private CIDR allowlist | Medium | `ADMIN_API_TOKEN` is required in production, so network-only access is defense-in-depth, not the sole control. |

---

## 3. Deployment Readiness

### What's Done

| Area | Status | Notes |
|------|--------|-------|
| Docker prod setup | Done | Multi-stage build, Caddy TLS, Let's Encrypt |
| Database migrations | Done | 26 migrations, expand-only policy, auto-run on startup |
| Graceful shutdown | Done | 10s drain, SIGTERM handling, all components stopped |
| Health checks | Done | `/health` with node connectivity check |
| Config validation | Done | `Validate()` enforces secrets, admin token, verifier ID in prod |
| Dev shortcuts blocked | Done | Compile-time build tags + runtime env checks |
| TLS | Done | Caddy auto-provisions Let's Encrypt certs, HTTP/3 support |
| CORS | Done | Explicit origin allowlist required in production |
| Rate limiting | Done | Per-group RPS + daily limits via RBAC |
| Admin auth | Done | localhostOnly + X-Admin-Token + JWT admin claim |
| Travel rule compliance | Done | Sanctions, thresholds, fail-closed on missing price |
| Runtime tracing | Done | `debug_traceCall` on every tx, CALL/CREATE validation |
| Token revocation | Done | DB blacklist, ban cascades to refresh tokens |
| Security headers | Done | CSP, X-Frame-Options, nosniff, Referrer-Policy |
| Cross-org isolation | Done | Contracts bound to orgs, pre-registration for CREATE |
| Structured logging | Done | `log/slog` across all files, JSON in production, text in dev |
| Prometheus metrics | Done | HTTP, JSON-RPC, RBAC, compliance, auth, pricing, SIEM, DB pool metrics; `/metrics` endpoint (private network only) |

### Production Environment Variables

**Required (server won't start without these in `ENVIRONMENT=production`):**

```bash
ENVIRONMENT=production
JWT_SECRET=<random-256-bit>              # openssl rand -hex 32
JWT_REFRESH_SECRET=<random-256-bit>      # openssl rand -hex 32
VERIFIER_ID=did:privado:...              # Your Privado verifier DID
ADMIN_API_TOKEN=<random-256-bit>         # openssl rand -hex 32
DATABASE_URL=postgres://user:pass@host:5432/privacy_proxy?sslmode=require
NODE_URL=http://your-ethereum-node:8545
```

**Strongly recommended:**

```bash
BASE_URL=https://api.yourdomain.com      # Public URL for OAuth callbacks
CORS_ALLOWED_ORIGINS=https://app.yourdomain.com
BILLIONS_ISSUER_DID=did:...              # Billions PoH issuer DID
REQUIRE_PROOF_OF_HUMANITY=true           # Default true in prod
ENABLE_RUNTIME_TRACING=true              # Transaction validation
ENABLE_TRAVEL_RULE=true                  # FATF compliance
```

**Optional:**

```bash
PRIVADO_RPC_URL=https://rpc-mainnet.privado.id    # Default
IPFS_GATEWAY=https://ipfs-proxy-cache.privado.id   # Default
ENS_RESOLVER_URL=https://eth.llamarpc.com           # Default
AZURE_AD_CLIENT_ID=                                 # If using Azure AD SSO
AZURE_AD_CLIENT_SECRET=
AZURE_AD_TENANT_ID=common
SIEM_WEBHOOK_URL=                                   # SIEM integration
RETENTION_ACCESS_LOGS=2160h                          # 90 days default
RETENTION_COMPLIANCE_LOGS=61320h                     # ~7 years default
```

**Automatically enforced in production (cannot override):**

```
MOCK_SIGNATURES=false
ALLOW_MOCK_LOGIN=false
DEMO_AUTO_AUTH_DELAY=0
```

### Deployment Steps

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with production values (see above)

# 2. Start services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# 3. Verify health
curl https://api.yourdomain.com/health

# 4. Bootstrap first admin
curl -X POST https://api.yourdomain.com/api/v1/admin/orgs \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slug": "my-org", "name": "My Organization"}'

# 5. Create group with admin claim, add users, etc.
# See docs/admin-auth-bootstrap.md for full bootstrap guide
```

### Database Migrations

Migrations run automatically on startup via `db.New()`. No manual migration step needed.

- **Policy:** Expand-only (no DROP TABLE/COLUMN in production)
- **Current:** 26 migrations (001–026)
- **Tool:** Tern v2 with Go embed
- **Manual check:** `go run ./cmd/migrate` to verify status

---

## 4. Remaining TODOs in Code

Minor items only — no production blockers:

| Location | Issue | Severity |
|----------|-------|----------|
| `e2e/.../20-cache-invalidation.spec.ts:176` | Intermittent test failure (cache race condition) | Medium |
| `e2e/.../07-historical-state.spec.ts:239` | Privacy gap check for historical state queries | Medium |

---

## 5. Post-MVP Improvements

### Short-term (recommended for first production sprint)

1. **Auto-set KYC from ProofOfHumanity verification** — Remove manual admin step (pending Billions schema clarification)
2. ~~**Structured logging**~~ — **Done.** Migrated all `log.Printf` to `log/slog` across 21 files. JSON output in production (`ENVIRONMENT=production`), text in dev. Structured key-value pairs on all log entries.
3. ~~**Prometheus metrics**~~ — **Done.** Dedicated registry with HTTP, JSON-RPC, RBAC, compliance, auth, pricing, SIEM, and DB pool metrics. `/metrics` endpoint restricted to private network. Custom `sql.DB` stats collector.

### Medium-term

4. **Dynamic issuer registry** — Store allowed issuers in DB, hot-reload without deploy
5. **Multi-credential support** — Configure ZK queries in DB, support AND/OR logic for multiple credential types
6. **Credential expiry tracking** — Notify users before credentials expire, auto-prompt re-auth
7. **Log aggregation** — SIEM webhook integration exists; wire it to your observability stack

### Not Needed for MVP

8. PKCE on Azure OAuth (backend uses client secret)
9. Rate limiting on admin endpoints (network-isolated)
10. Configurable CIDR allowlist for admin middleware
