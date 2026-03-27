# Privacy Proxy

A privacy-preserving JSON-RPC proxy for Ethereum nodes with ZK-proof authentication and hierarchical RBAC.

## Quick Start

```bash
# Start the stack
make run

# Open admin UI
open http://localhost:5173
```

In development mode, click the flask icon on the login page for instant mock authentication. Mock users are automatically granted admin access.

## Architecture

```
┌─────────────┐     ┌───────────────────────────────────────┐     ┌──────────────┐
│   Client    │────>│            Privacy Proxy              │────>│  Ethereum    │
│  (Wallet)   │     │                                       │     │    Node      │
└─────────────┘     │  ┌─────────┐  ┌──────┐  ┌─────────┐  │     └──────────────┘
                    │  │  Auth   │  │ RBAC │  │  Proxy  │  │
                    │  │ (ZK/JWT)│  │      │  │         │  │
                    │  └─────────┘  └──────┘  └─────────┘  │
                    │                  │                    │
                    │           ┌──────▼──────┐            │
                    │           │  PostgreSQL │            │
                    │           └─────────────┘            │
                    └───────────────────────────────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| proxy-backend | 8080 | API server |
| proxy-frontend | 5173 | Admin UI |
| postgres | 5432 | Database |
| anvil | 8545 | Local Ethereum node |

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](site/src/app/docs/getting-started/page.mdx) | Installation, setup, first run |
| [Architecture](site/src/app/docs/architecture/page.mdx) | System overview, request flow, components |
| [Authentication](site/src/app/docs/authentication/page.mdx) | ZK-proof auth, ETH address linking |
| [Azure AD / SSO](site/src/app/docs/azure-ad/page.mdx) | Microsoft Entra ID integration |
| [RBAC](site/src/app/docs/rbac/page.mdx) | Role-based access control system |
| [API Reference](site/src/app/docs/api/page.mdx) | Complete HTTP endpoint documentation |
| [Security](site/src/app/docs/security/page.mdx) | Request filtering, cross-org isolation |
| [Compliance](site/src/app/docs/compliance/page.mdx) | Travel rule enforcement |
| [Selective Disclosure](site/src/app/docs/disclosure/page.mdx) | Privacy-aware data sharing |
| [Deployment](site/src/app/docs/deployment/page.mdx) | Deploying contracts through the proxy |
| [Governance](site/src/app/docs/governance/page.mdx) | Multi-party RBAC approvals |
| [Configuration](site/src/app/docs/configuration/page.mdx) | Environment variables reference |
| [Testing](site/src/app/docs/testing/page.mdx) | Unit, E2E, and Playwright tests |
| [Troubleshooting](site/src/app/docs/troubleshooting/page.mdx) | Common issues and fixes |

To run the docs site locally:

```bash
make site-dev
# Open http://localhost:3000
```

## Testing

```bash
make test-unit   # Go unit tests
make e2e         # Playwright E2E tests (131+ tests)
```

**Database layer tests (uses testcontainers automatically):**
```bash
go test ./internal/db/... -v
```

**Note**: Database tests automatically use testcontainers (Docker required).

### E2E Tests

E2E tests use Playwright and Docker to run a full integration suite with 131+ tests covering RBAC, authentication, and access control.

**Run all E2E tests:**
```bash
make e2e
# This starts all services and runs Playwright tests
```

**Or run manually:**
```bash
# Start services
docker-compose -f docker-compose.e2e.yml up -d postgres anvil proxy-backend

# Run tests
docker-compose -f docker-compose.e2e.yml run --rm playwright npm test

# Stop services
docker-compose -f docker-compose.e2e.yml down
```

**Run specific test suites:**
```bash
# Run only function selector tests
docker-compose -f docker-compose.e2e.yml run --rm playwright npm test -- --grep "Function Selector"

# Run only hierarchy tests
docker-compose -f docker-compose.e2e.yml run --rm playwright npm test -- --grep "Hierarchy"
```

## Test Identities (Development)

For manual testing of privacy redaction from different user perspectives, the project includes a setup script that creates pre-configured test accounts with well-known Anvil addresses.

### Setup

```bash
# Requires: services running, ALLOW_MOCK_LOGIN=true, cast + jq installed
./scripts/setup-test-accounts.sh
```

This creates:

| Name | DID | Address (Anvil) | Role |
|------|-----|-----------------|------|
| Alice | `did:test:alice` | `0x7099...79C8` (account 1) | Alpha Corp deployer |
| Bob | `did:test:bob` | `0x3C44...93BC` (account 2) | Alpha Corp reader |
| Charlie | `did:test:charlie` | `0x90F7...3906` (account 3) | Beta Inc deployer |
| Dave | `did:test:dave` | `0x15d3...A65` (account 4) | No org (anonymous) |

The script also creates orgs, groups with RBAC claims, ETH address links, a disclosure grant (Bob can view Alice's data), and ETH transfers between accounts.

### Identity Picker

When `ALLOW_MOCK_LOGIN=true` (dev builds), the login page shows a **quick login** panel with the test identities. Click a name to instantly authenticate as that user — works for both direct login and OAuth (block explorer SSO).

The identity list is fetched from `GET /api/v1/dev/test-identities`, which only exists in `mockauth` builds and returns 404 in production.

### Re-running

The script is idempotent. Run it again after an Anvil reset to recreate the test data.

## Access Control

This proxy implements a hierarchical Role-Based Access Control (RBAC) system for fine-grained permission management.

### Key Features

- **Multi-tenant organizations** with isolated permission hierarchies
- **Restrictive inheritance**: Child groups can only narrow parent permissions
- **Dual membership support**: Admin assignment and ZK-attested credentials
- **Contract ownership tracking** with special abilities
- **Advanced Tracing**: Secure, rate-limited access to `debug_traceTransaction` and `debug_traceCall` with cross-org trace-tree validator
- **Batch Management**: Comprehensive UI for batch-moving contracts and batch-deleting groups

### Quick Start

```bash
# List organizations
curl http://localhost:8080/api/orgs

# Create a group
curl -X POST http://localhost:8080/api/orgs/{org_id}/groups \
  -H "Content-Type: application/json" \
  -d '{"slug": "engineering", "name": "Engineering Team"}'

# Set permissions
curl -X PUT http://localhost:8080/api/orgs/{org_id}/groups/{group_id}/permissions \
  -H "Content-Type: application/json" \
  -d '{"allow_methods": ["eth_call", "eth_getBalance"]}'

# Check effective permissions
curl http://localhost:8080/api/users/{user_id}/effective-permissions
```

See [RBAC Documentation](docs/RBAC.md) for detailed use cases and API reference.

## Selective Disclosure

The system includes a selective disclosure feature for compliance and audit use cases. Users can grant time-limited access to their data with configurable privacy levels.

### Disclosure Levels

| Level | Description |
|-------|-------------|
| **Full** | Real addresses visible - for regulatory/legal requirements |
| **Pseudonymous** | Consistent pseudonyms (e.g., `Address-KDCM`) - for audits |
| **Redacted** | All addresses hidden as `[REDACTED]` - minimal disclosure |

### Quick Example

```bash
# Auditor creates a disclosure request
curl -X POST http://localhost:8080/api/v1/disclosure/requests \
  -H "Content-Type: application/json" \
  -d '{
    "target_user_id": "user-123",
    "scope": {
      "disclosure_level": "pseudonymous",
      "date_range": {"start": "2024-01-01", "end": "2024-12-31"}
    },
    "reason": "Annual financial audit"
  }'

# User approves the request
curl -X POST http://localhost:8080/api/v1/disclosure/requests/{id}/approve \
  -d '{"grant_duration_days": 30}'

# Auditor views pseudonymized transactions
curl http://localhost:8080/api/v1/explorer/grant/{grant_id}/{address_id}/transactions
# Returns: {"from": "Address-KDCM", "to": "External-7E56", ...}
```

See [Disclosure Documentation](docs/DISCLOSURE.md) for the complete guide.

## Admin Authentication

The admin dashboard and management API use a layered authentication model with two credential types and network-level defense in depth.

### Authentication Methods

| Method | Header | Use case |
|--------|--------|----------|
| **Admin token** | `X-Admin-Token: <token>` | M2M scripts, CI pipelines, bootstrap |
| **JWT with admin claim** | `Authorization: Bearer <jwt>` | Browser-based admin dashboard access |

Both methods are accepted by the `adminAuthMiddleware`. If neither credential is supplied and `ADMIN_API_TOKEN` is **not** configured, the middleware is a no-op (dev mode -- localhost/network controls are the only gate).

### Bootstrap Flow

When deploying a fresh instance, no users exist yet. Follow these steps to promote the first admin:

1. **Set `ADMIN_API_TOKEN`** in your environment (docker-compose, .env, etc.).
2. **Use the token to call admin APIs** -- create an org, a group with the `admin` claim, and a user record:
   ```bash
   # Create an org
   curl -X POST http://localhost:8080/api/v1/admin/rbac/orgs \
     -H "X-Admin-Token: $ADMIN_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"slug": "myorg", "name": "My Organization"}'

   # Create a group with the admin claim
   curl -X POST http://localhost:8080/api/v1/admin/rbac/orgs/{org_id}/groups \
     -H "X-Admin-Token: $ADMIN_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"slug": "admins", "name": "Administrators"}'

   # Grant admin claim to the group
   curl -X PUT http://localhost:8080/api/v1/admin/rbac/orgs/{org_id}/groups/{group_id}/access \
     -H "X-Admin-Token: $ADMIN_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"claims": ["admin"]}'

   # Add the first user to the admin group
   curl -X POST http://localhost:8080/api/v1/admin/rbac/orgs/{org_id}/groups/{group_id}/members \
     -H "X-Admin-Token: $ADMIN_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"user_id": "<user-uuid>", "source": "admin_assigned"}'
   ```
3. **That user authenticates via Privado ID** (the normal ZK-proof login flow) and receives a JWT.
4. **The frontend `RequireAdmin` component** calls `GET /api/v1/me/admin-status` with the JWT. The backend looks up the user's group memberships and checks for the `admin` claim. If present, the admin dashboard is unlocked.
5. **The admin can now promote other users** through the dashboard UI -- no further use of `X-Admin-Token` is required for day-to-day operations.

### Frontend Gating

The admin dashboard is wrapped in two React guards (see `frontend/src/main.tsx`):

```tsx
<RequireAuth>
  <RequireAdmin>
    <AdminApp />
  </RequireAdmin>
</RequireAuth>
```

- **`RequireAuth`** -- redirects unauthenticated users to the login page.
- **`RequireAdmin`** -- calls `GET /api/v1/me/admin-status` and renders an "Access Denied" screen if the user lacks the `admin` claim.

### Admin Status API

```
GET /api/v1/me/admin-status
Authorization: Bearer <jwt>

Response: {"is_admin": true}   // or {"is_admin": false}
```

Requires a valid JWT. Returns whether the authenticated user has the `admin` RBAC claim via any group membership. The query joins `user_memberships` with `group_access` and checks the claims array (see `HasAdminClaim` in `internal/db/rbac_store_user.go`).

### Network-Level Defense in Depth

All admin routes additionally pass through `localhostOnlyMiddleware`, which checks the **raw TCP peer address** (not `X-Forwarded-For`) against private network CIDRs:

- `127.0.0.1/32`, `::1/128` -- localhost
- `172.16.0.0/12`, `192.168.0.0/16`, `10.0.0.0/8` -- RFC 1918
- `100.64.0.0/10` -- Tailscale / CGNAT

This means even if an attacker obtains a valid admin JWT, they cannot reach admin endpoints unless their TCP connection originates from a private network (e.g., the Docker bridge or a Tailscale mesh).

### Dev Mode

When `ADMIN_API_TOKEN` is **not set** and no JWT is provided, the admin auth middleware passes requests through without authentication. This is intended for local development only -- `localhostOnlyMiddleware` still restricts access to private-network callers.

## Security Considerations

- **JWT Secrets**: In production, always set `JWT_SECRET` and `JWT_REFRESH_SECRET` to strong, random values
- **Token Revocation**: Revoked tokens are stored in PostgreSQL. For high-volume production, consider Redis for faster lookups
- **Management API**: Protected by localhost-only middleware (accessible from Docker network)
- **Token Rotation**: Refresh tokens are rotated on each refresh for enhanced security
- **Privado RPC**: Use your own RPC node or trusted service (Infura, Alchemy) for production
- **RBAC Admin**: RBAC admin endpoints are protected by localhost-only middleware + admin auth (token or JWT with admin claim)

## License

MIT
