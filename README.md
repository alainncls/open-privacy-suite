# Privacy Proxy for Erigon Node

A privacy proxy service that sits in front of an Erigon Ethereum node, providing identity-based access control with KYC verification and method whitelisting.

## Architecture

```
Client
  |
  | JSON-RPC + Authorization: Bearer <token>
  v
Privacy Proxy (this service)
  |
  | (validates identity, checks policy)
  v
Ethereum Node (Erigon/geth)
```

## Features

- **Identity Resolution**: Integrates with Billions service (mocked for development) to resolve user identity from Bearer tokens
- **Access Control**: Policy-based access control with:
  - KYC verification (required for all users)
  - Method whitelisting (e.g., allow `eth_call` but not `eth_sendTransaction`)
  - Ban/unban functionality
- **Access Logging**: Tracks all requests with user ID, method, status code, and IP address
- **Management UI**: React dashboard for viewing logs and managing access policies
- **Comprehensive Testing**: Unit tests and E2E tests for full request flow

## Project Structure

```
privacy-proxy/
├── cmd/
│   ├── server/          # Main server application
│   └── migrate/         # Database migration tool
├── internal/
│   ├── access/          # Access control logic
│   ├── config/          # Configuration management
│   ├── db/              # Database layer (PostgreSQL)
│   ├── identity/        # Identity resolution (Billions integration)
│   ├── proxy/           # Proxy forwarding logic
│   └── server/          # HTTP server and routes
├── e2e/                 # End-to-end tests
│   └── mock-node/       # Mock Erigon node for testing
├── frontend/            # React + TypeScript UI
└── data/                # Database storage (gitignored)
```

## Quick Start

### Prerequisites

- Go 1.21+
- Node.js 18+ (for frontend)
- PostgreSQL 12+ (or use Docker Compose)
- Docker & Docker Compose (optional, for mock node and PostgreSQL)

### Backend Setup

1. Install dependencies:
```bash
go mod download
```

2. Set up PostgreSQL database:
```bash
# Option 1: Use Docker Compose (recommended)
docker-compose up -d postgres

# Option 2: Use local PostgreSQL
createdb privacy_proxy
```

3. Run database migrations:
```bash
# Set DATABASE_URL if not using default
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"

make db-migrate
# or
go run ./cmd/migrate
```

3. Start the server:
```bash
make dev
# or
go run ./cmd/server
```

The server will start on `http://localhost:8080`

### Frontend Setup

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Start dev server:
```bash
npm run dev
```

The UI will be available at `http://localhost:5173`

### Using Docker Compose

Start all services (PostgreSQL, mock Billions, mock Erigon node, backend, and frontend):

```bash
docker-compose up -d
```

This will start:
- **PostgreSQL** on port 5432
- **Mock Billions** service on port 9000
- **Mock Erigon node** on port 8545
- **Backend API** on port 8080
- **Frontend UI** on port 5173

Access the services:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8080
- Management API: http://localhost:8080/api (localhost-only)

View logs:
```bash
docker-compose logs -f
```

Stop all services:
```bash
docker-compose down
```

## Usage

### Making Requests

Send JSON-RPC requests with an `Authorization` header:

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer user_123" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [],
    "id": 1
  }'
```

### Managing Policies

Use the UI at `http://localhost:5173` or the API:

**List policies:**
```bash
curl http://localhost:8080/api/policies
```

**Create/Update policy:**
```bash
curl -X PUT http://localhost:8080/api/policies/billions:user_123 \
  -H "Content-Type: application/json" \
  -d '{
    "external_id": "billions:user_123",
    "kyc": true,
    "allow_methods": ["eth_call", "eth_getBalance"],
    "banned": false,
    "note": "Test user"
  }'
```

**View access logs:**
```bash
curl http://localhost:8080/api/logs?limit=100
```

## Configuration

Environment variables:

- `PORT` - Server port (default: 8080)
- `NODE_URL` - Ethereum node URL (default: http://localhost:8545)
- `DATABASE_URL` - PostgreSQL connection string (default: postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable)
- `BILLIONS_URL` - Billions service URL (default: http://localhost:9000)

## Testing

### Unit Tests

**First, set up test databases:**
```bash
# Option 1: Use setup script
./scripts/setup-test-db.sh

# Option 2: Create manually
createdb privacy_proxy_test
createdb privacy_proxy_e2e_test
```

**Then run tests:**
```bash
make test-unit
# or
go test ./internal/...
```

### E2E Tests

1. Start mock node:
```bash
cd e2e/mock-node
npm install
npm start
# In another terminal:
```

2. Run E2E tests:
```bash
make test-e2e
# or
go test ./e2e/...
```

### All Tests

```bash
make test
```

## API Endpoints

### Proxy Endpoint

- `POST /` - JSON-RPC proxy endpoint (requires `Authorization: Bearer <token>`)

### Management API

**Note**: Management API endpoints are only accessible from localhost for security. When running in Docker, you can still access them from your host machine via `localhost:8080`.

- `GET /api/policies` - List all access policies
- `GET /api/policies/:id` - Get specific policy
- `POST /api/policies` - Create new policy
- `PUT /api/policies/:id` - Update policy
- `GET /api/logs?limit=N` - Get access logs (default limit: 100)

## Data Model

### Access Policy

```json
{
  "external_id": "billions:user_123",
  "kyc": true,
  "allow_methods": ["eth_call", "eth_getBalance"],
  "banned": false,
  "note": "Internal tester"
}
```

### Access Log

```json
{
  "id": 1,
  "external_id": "billions:user_123",
  "method": "eth_call",
  "status_code": 200,
  "ip_address": "127.0.0.1",
  "created_at": "2024-01-01T00:00:00Z"
}
```

## Development

### Adding New Features

1. Write tests first (TDD approach)
2. Implement feature
3. Run tests: `make test`
4. Update documentation

### Database Migrations

Migrations run automatically on startup. To manually run:

```bash
make db-migrate
```

## Production Considerations

- Replace mocked Billions integration with real service
- Configure PostgreSQL with proper credentials and SSL
- Add HTTPS/TLS
- Set up monitoring and alerting
- Configure proper CORS for frontend

## License

MIT
