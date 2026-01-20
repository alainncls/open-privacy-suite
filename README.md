# Privacy Proxy

A privacy-preserving proxy service for Ethereum nodes (Erigon) that enforces access control based on Privado ID zero-knowledge proofs and KYC verification.

## Features

- **Privado ID Integration**: Verifies zero-knowledge proofs (JWZ tokens) from Privado ID protocol
- **JWT Authentication**: Issues and validates JWT tokens for authenticated requests
- **Access Control**: Enforces KYC requirements and method-level permissions
- **Token Management**: Supports refresh tokens, token revocation, and automatic cleanup
- **Management UI**: Web interface for managing access policies and viewing logs
- **Comprehensive Testing**: Unit and E2E tests for all components

## Architecture

```
Client
  |
  | POST /auth (JWZ proof)
  v
Privacy Proxy
  |
  | Verify JWZ → Issue JWT
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

## Authentication Flow

1. **Initial Authentication** (`POST /auth`):
   - Client sends Privado ID JWZ proof
   - Server verifies proof using `go-iden3-auth`
   - If valid, server issues:
     - Access token (JWT, 30 min TTL)
     - Refresh token (JWT, 7 days TTL, stored in DB)

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
- **Mock Privado ID** service on port 9000 (for testing)
- **Mock Erigon node** on port 8545
- **Backend API** on port 8080
- **Frontend UI** on port 5173

Access the services:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8080
- Management API: http://localhost:8080/api (localhost-only)

## Configuration

Environment variables:

- `PORT` - Server port (default: 8080)
- `NODE_URL` - Ethereum node URL (default: http://localhost:8545)
- `DATABASE_URL` - PostgreSQL connection string (default: postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable)
- `PRIVADO_RPC_URL` - Privado network RPC URL (default: https://rpc-mainnet.privado.id)
- `JWT_SECRET` - Secret for signing access tokens (auto-generated if empty, dev only)
- `JWT_REFRESH_SECRET` - Secret for signing refresh tokens (auto-generated if empty, dev only)

## Usage

### 1. Authenticate with Privado ID

```bash
curl -X POST http://localhost:8080/auth \
  -H "Content-Type: application/json" \
  -d '{
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

**Business logic tests (no database required):**
```bash
go test ./internal/access/... -v
```

**Database layer tests (uses testcontainers automatically):**
```bash
go test ./internal/db/... -v
```

**All unit tests:**
```bash
make test-unit
# or
go test ./internal/... -v
```

**Note**: Database tests automatically use testcontainers (Docker required). Business logic tests use mocks and don't need PostgreSQL.

### E2E Tests

1. Start mock services:
```bash
docker-compose up -d postgres erigon-mock
```

2. Run E2E tests:
```bash
make test-e2e
# or
go test ./e2e/...
```

## Security Considerations

- **JWT Secrets**: In production, always set `JWT_SECRET` and `JWT_REFRESH_SECRET` to strong, random values
- **Token Revocation**: Revoked tokens are stored in PostgreSQL. For high-volume production, consider Redis for faster lookups
- **Management API**: Protected by localhost-only middleware (accessible from Docker network)
- **Token Rotation**: Refresh tokens are rotated on each refresh for enhanced security
- **Privado RPC**: Use your own RPC node or trusted service (Infura, Alchemy) for production

## License

MIT
