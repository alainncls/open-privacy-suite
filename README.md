# Privacy Proxy

A privacy-preserving proxy service for Ethereum nodes (Erigon) that enforces access control based on Privado ID zero-knowledge proofs and KYC verification.

## Features

- **Privado ID Integration**: Verifies zero-knowledge proofs (JWZ tokens) from Privado ID protocol
- **ProofOfHumanity (Billions)**: Requires proof of liveness via Billions ProofOfHumanity credential
- **JWT Authentication**: Issues and validates JWT tokens for authenticated requests
- **RBAC Access Control**: Multi-tenant, hierarchical role-based access control with:
  - Method-level permissions (which JSON-RPC methods users can call)
  - Contract-level permissions (which contracts users can interact with)
  - Function selector restrictions (which contract functions users can call)
  - Rate limiting (RPS and daily limits)
- **Token Management**: Supports refresh tokens, token revocation, and automatic cleanup
- **Management UI**: Web interface for managing access policies and viewing logs
- **Comprehensive Testing**: 131+ e2e tests covering all RBAC scenarios

## Architecture

```
Client
  |
  | POST /auth/request
  v
Privacy Proxy
  |
  | Create Auth Request → Return to Client
  v
Client (with Auth Request)
  |
  | Open Wallet with Auth Request
  v
Wallet
  |
  | Generate Proof → POST /auth/callback
  v
Privacy Proxy
  |
  | Verify Proof → Issue JWT
  v
Client (with JWT)
  |
  | POST / (JSON-RPC + JWT)
  v
Privacy Proxy
  |
  | Validate JWT → Check Policy → Proxy
  v
Ethereum Node
```

## Explorer Integration

Privacy-proxy can be integrated with block explorers to provide privacy-aware address visibility. The explorer calls internal APIs to check which addresses a user can view based on their identity and disclosure grants.

```
┌─────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│  Block Explorer │     │    Privacy-Proxy    │     │  Privado App │
│   (OAuth Client)│     │  (Identity Provider)│     │  (ZK Proofs) │
└────────┬────────┘     └──────────┬──────────┘     └──────┬───────┘
         │                         │                        │
         │ 1. User clicks          │                        │
         │    "Sign in with        │                        │
         │     Privado"            │                        │
         │                         │                        │
         │ 2. GET /oauth/authorize │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │                         │ 3. Show QR code        │
         │                         │    (auth request)      │
         │                         │ ──────────────────────>│
         │                         │                        │
         │                         │ 4. User scans,         │
         │                         │    submits ZK proof    │
         │                         │ <──────────────────────│
         │                         │                        │
         │ 5. Redirect with        │                        │
         │    ?code=xxx&state=yyy  │                        │
         │ <───────────────────────│                        │
         │                         │                        │
         │ 6. POST /oauth/token    │                        │
         │    (exchange code)      │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │ 7. Return JWT           │                        │
         │    (contains DID)       │                        │
         │ <───────────────────────│                        │
         │                         │                        │
```

See [SSO_IMPLEMENTATION.md](SSO_IMPLEMENTATION.md) for detailed OAuth/SSO documentation.

## Authentication Flow

1. **Request Authentication** (`POST /auth/request`):
   - Client requests authentication
   - Server creates Privado ID authorization request (proof request)
   - Server stores session and returns:
     - Session ID
     - Authorization request (to be sent to user's wallet)

2. **User Approves in Wallet**:
   - User opens wallet/app with the authorization request
   - Wallet generates zero-knowledge proof based on user's credentials
   - Wallet automatically sends proof to server's callback URL

3. **Wallet Callback** (`POST /auth/callback?session=<sessionId>`):
   - Wallet sends proof to callback URL
   - Server verifies proof against original authorization request
   - If valid, server issues:
     - Access token (JWT, 30 min TTL)
     - Refresh token (JWT, 7 days TTL, stored in DB)

4. **Manual Verification** (`POST /auth/verify`) - Development Only:
   - Alternative flow for testing/development
   - Client manually submits session ID + proof
   - Server verifies and issues JWT tokens

2. **API Requests**:
   - Client includes `Authorization: Bearer <access_token>`
   - Server validates JWT and checks revocation
   - Server extracts identity and checks access policies

3. **Token Refresh** (`POST /refresh`):
   - Client sends refresh token
   - Server validates and issues new access + refresh tokens
   - Old refresh token is revoked (token rotation)

4. **Token Revocation** (`POST /revoke`):
   - Client can revoke refresh tokens
   - Revoked tokens are stored in database

## Prerequisites

- Go 1.21+
- PostgreSQL 15+
- Node.js 20+ (for frontend)
- Docker & Docker Compose (optional, for containerized setup)

## Setup

### Local Development

1. **Install dependencies:**
```bash
go mod download
cd frontend && npm install
```

2. **Set up PostgreSQL:**
```bash
createdb privacy_proxy
createdb privacy_proxy_test
createdb privacy_proxy_e2e_test
```

3. **Run migrations:**
```bash
make db-migrate
```

4. **Start services:**
```bash
# Terminal 1: Backend
go run ./cmd/server

# Terminal 2: Frontend
cd frontend && npm run dev
```

### Docker Setup

Start all services (PostgreSQL, mock services, backend, frontend):

```bash
docker-compose up -d
```

This will start:
- **PostgreSQL** on port 5432
- **Anvil** (local Ethereum node) on port 8545
- **Backend API** on port 8080
- **Frontend UI** on port 5173

Access the services:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8080
- Management API: http://localhost:8080/api (localhost-only)

### Network Access (LAN)

To access services from other devices on your local network, set `BASE_URL` to your machine's IP:

```bash
# Get your local IP
ipconfig getifaddr en0  # macOS
hostname -I | awk '{print $1}'  # Linux

# Start with network-accessible URL (include http:// prefix!)
BASE_URL="http://YOUR_IP:8080" docker-compose up -d
```

### Running with Block Explorer

The explorer integrates with privacy-proxy for authentication and privacy-aware address visibility.

```bash
# 1. Start privacy-proxy first
BASE_URL="http://YOUR_IP:8080" docker-compose up -d

# 2. Start explorer (from explorer directory)
SSO_REDIRECT_URI="http://YOUR_IP:3000/api/auth/callback" \
VITE_RPC_URL="http://YOUR_IP:8545" \
docker-compose -f docker-compose.privacy-proxy.yml up -d
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8080` | Public URL of privacy-proxy API (**must include http://**) |
| `SSO_REDIRECT_URI` | `http://localhost:3000/api/auth/callback` | OAuth callback URL for explorer |
| `VITE_RPC_URL` | `http://localhost:8545` | Ethereum RPC URL for explorer frontend |

**Port Reference:**

| Service | Port | Description |
|---------|------|-------------|
| Privacy Proxy API | 8080 | Main API endpoint |
| Privacy Proxy Frontend | 5173 | Management UI |
| PostgreSQL | 5432 | Privacy-proxy database |
| Anvil | 8545 | Local Ethereum node |
| Explorer Frontend | 3000 | Block explorer UI |
| Explorer Backend | 8081 | Explorer API |
| Explorer PostgreSQL | 5433 | Explorer database (different port to avoid conflict)

## Configuration

Environment variables:

### Required for Production
- `VERIFIER_ID` - Your verifier DID or identifier
- `JWT_SECRET` - Secret for signing access tokens (strong, random value)
- `JWT_REFRESH_SECRET` - Secret for signing refresh tokens (strong, random value)
- `BILLIONS_ISSUER_DID` - Billions issuer DID for ProofOfHumanity verification

### Optional Configuration
- `PORT` - Server port (default: 8080)
- `NODE_URL` - Ethereum node URL (default: http://localhost:8545)
- `DATABASE_URL` - PostgreSQL connection string (default: postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable)
- `PRIVADO_RPC_URL` - Privado network RPC URL (default: https://rpc-mainnet.privado.id)
- `IPFS_GATEWAY` - IPFS gateway for schema resolution (default: https://ipfs-proxy-cache.privado.id)
- `BASE_URL` - Base URL for callback (default: http://localhost:8080)
- `ENVIRONMENT` - "production" or "development" (default: development)
- `REQUIRE_PROOF_OF_HUMANITY` - Require ProofOfHumanity credential (default: true in production, false in development)

## Usage

### 1. Request Authentication

```bash
curl -X POST http://localhost:8080/auth/request \
  -H "Content-Type: application/json"
```

Response:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "auth_request": {
    "id": "...",
    "type": "https://iden3-communication.io/authorization/1.0/request",
    "body": {
      "callbackUrl": "http://localhost:8080/auth/callback?session=550e8400-e29b-41d4-a716-446655440000",
      "reason": "Authenticate to access Ethereum node"
    }
  }
}
```

### 2. User Approves in Wallet

The user opens their Privado wallet/app with the authorization request. The wallet generates a proof and automatically sends it to the callback URL.

### 3. Receive JWT Tokens

The wallet callback automatically receives the tokens. For manual testing (development only):

```bash
curl -X POST http://localhost:8080/auth/verify \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "jwz_token": "<privado_jwz_proof>"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### 2. Make JSON-RPC Requests

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [],
    "id": 1
  }'
```

### Using with Foundry/Hardhat

For deploying contracts with standard Ethereum development tools, set the `ETH_RPC_HEADERS` environment variable:

```bash
# Set auth header for Foundry
export ETH_RPC_HEADERS="Authorization: Bearer <access_token>"

# Deploy with forge
forge script script/Deploy.s.sol --rpc-url http://localhost:8080/rpc --broadcast
```

See [Contract Deployment Workflow](docs/DEPLOYMENT_WORKFLOW.md) for complete instructions.

### 3. Refresh Token

```bash
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'
```

### 4. Revoke Token

```bash
curl -X POST http://localhost:8080/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'
```

## Testing

### Unit Tests

**All unit tests:**
```bash
make test-unit
# or
go test ./internal/... -v
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

## Access Control

This proxy implements a hierarchical Role-Based Access Control (RBAC) system for fine-grained permission management.

### Key Features

- **Multi-tenant organizations** with isolated permission hierarchies
- **Restrictive inheritance**: Child groups can only narrow parent permissions
- **Dual membership support**: Admin assignment and ZK-attested credentials
- **Contract ownership tracking** with special abilities

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

## Security Considerations

- **JWT Secrets**: In production, always set `JWT_SECRET` and `JWT_REFRESH_SECRET` to strong, random values
- **Token Revocation**: Revoked tokens are stored in PostgreSQL. For high-volume production, consider Redis for faster lookups
- **Management API**: Protected by localhost-only middleware (accessible from Docker network)
- **Token Rotation**: Refresh tokens are rotated on each refresh for enhanced security
- **Privado RPC**: Use your own RPC node or trusted service (Infura, Alchemy) for production
- **RBAC Admin**: RBAC admin endpoints are protected by localhost-only middleware

## License

MIT
