# Configuration Reference

## Environment Variables

### Required in Production

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | Secret for signing access tokens |
| `JWT_REFRESH_SECRET` | Secret for signing refresh tokens |
| `VERIFIER_ID` | Your Privado verifier DID |
| `DATABASE_URL` | PostgreSQL connection string |

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server listen port |
| `NODE_URL` | `http://localhost:8545` | Target Ethereum node URL |
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable` | PostgreSQL connection |
| `ENVIRONMENT` | `development` | `production` or `development` |
| `BASE_URL` | `http://localhost:8080` | Public URL for auth callbacks |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `PRIVADO_RPC_URL` | `https://rpc-mainnet.privado.id` | Privado network RPC |
| `IPFS_GATEWAY` | `https://ipfs-proxy-cache.privado.id` | IPFS gateway for schemas |
| `JWT_SECRET` | (auto in dev) | Access token signing secret |
| `JWT_REFRESH_SECRET` | (auto in dev) | Refresh token signing secret |
| `VERIFIER_ID` | (required in prod) | Privado verifier DID |

### ProofOfHumanity (Billions)

| Variable | Default | Description |
|----------|---------|-------------|
| `BILLIONS_ISSUER_DID` | (none) | Billions issuer DID for PoH verification |
| `REQUIRE_PROOF_OF_HUMANITY` | `false` (dev) / `true` (prod) | Require PoH credential |

### Token TTLs

| Token | TTL | Notes |
|-------|-----|-------|
| Access Token | 30 minutes | Short-lived, use refresh to renew |
| Refresh Token | 7 days | Rotated on each refresh |
| Auth Session | 10 minutes | Time to complete auth flow |
| ETH Link Challenge | 5 minutes | Signature challenge expiry |

### Rate Limiting

Configured per-user via RBAC:
- `rate_limit_rps` - Requests per second (sliding window)
- `rate_limit_daily` - Daily request limit (resets UTC midnight)

---

## Environment Modes

### Development (`ENVIRONMENT=development`)

- `/auth/verify` endpoint enabled for manual testing
- JWT secrets auto-generated if not set
- `REQUIRE_PROOF_OF_HUMANITY` defaults to `false`
- Mock tokens accepted: `mock.{did}` or `mock.jwz.token.{did}`

### Production (`ENVIRONMENT=production`)

- `/auth/verify` endpoint disabled
- JWT secrets required
- `REQUIRE_PROOF_OF_HUMANITY` defaults to `true`
- `VERIFIER_ID` required

---

## Docker Configuration

### docker-compose.yml Services

| Service | Port | Purpose |
|---------|------|---------|
| `postgres` | 5432 | Database |
| `proxy-backend` | 8080 | API server |
| `proxy-frontend` | 5173 | Admin UI |
| `anvil` | 8545 | Local Ethereum node |

### E2E Testing (docker-compose.e2e.yml)

Replaces mock node with Anvil for realistic testing.

```bash
make e2e          # Run full suite
make e2e-debug    # Keep services running
make e2e-down     # Stop services
```

---

## Database

### Connection

Uses pgx v5 with standard `database/sql` interface.

```bash
# Local development
DATABASE_URL=postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable

# Docker
DATABASE_URL=postgres://postgres:postgres@postgres:5432/privacy_proxy?sslmode=disable
```

### Migrations

Uses Tern v2 with embedded migrations in `internal/db/migrations/`.

```bash
# Run migrations
make db-migrate

# Create new migration
make db-new-migration name=add_feature
```

**Migration Policy:** Expand-only in production. Never use DROP in UP migrations.

---

## Trusted Proxies

For Docker environments, the server trusts `X-Forwarded-For` from:
- `172.16.0.0/12` (Docker networks)
- `127.0.0.1` (localhost)

Configure in `internal/server/server.go` if needed.

---

## Example .env

```bash
# Required for production
ENVIRONMENT=production
JWT_SECRET=your-secure-secret-here
JWT_REFRESH_SECRET=your-refresh-secret-here
VERIFIER_ID=did:polygonid:polygon:main:your-verifier-did

# Database
DATABASE_URL=postgres://user:pass@host:5432/dbname?sslmode=require

# Ethereum node
NODE_URL=https://eth-mainnet.alchemyapi.io/v2/your-key

# Privado
PRIVADO_RPC_URL=https://rpc-mainnet.privado.id

# ProofOfHumanity (optional)
BILLIONS_ISSUER_DID=did:polygonid:polygon:main:billions-issuer-did
REQUIRE_PROOF_OF_HUMANITY=true

# Public URL
BASE_URL=https://your-domain.com
```
