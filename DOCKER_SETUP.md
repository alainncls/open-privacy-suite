# Docker Setup Guide

## Complete Docker Environment

The `docker-compose.yml` file sets up a complete development environment with all services:

### Services

1. **PostgreSQL** (port 5432)
   - Database: `privacy_proxy`
   - User: `postgres` / Password: `postgres`

2. **Mock Billions Service** (port 9000)
   - Identity verification endpoint: `GET /verify`
   - Accepts `Authorization: Bearer <token>`
   - Returns: `{subject, kyc, claims}`

3. **Mock Erigon Node** (port 8545)
   - JSON-RPC endpoint: `POST /`
   - Mock responses for common methods

4. **Backend API** (port 8080)
   - Proxy endpoint: `POST /`
   - Management API: `GET /api/*` (localhost-only)

5. **Frontend UI** (port 5173)
   - React dev server
   - Proxies `/api` to backend

## Quick Start

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Service URLs

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8080
- **Management API**: http://localhost:8080/api (localhost-only)
- **Mock Billions**: http://localhost:9000
- **Mock Erigon**: http://localhost:8545
- **PostgreSQL**: localhost:5432

## Testing the Setup

1. **Create a policy** (from localhost):
```bash
curl -X POST http://localhost:8080/api/policies \
  -H "Content-Type: application/json" \
  -d '{
    "external_id": "billions:test_user",
    "kyc": true,
    "allow_methods": ["eth_call", "eth_getBalance"],
    "banned": false
  }'
```

2. **Make a proxy request**:
```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer test_user" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [],
    "id": 1
  }'
```

3. **View logs**:
```bash
curl http://localhost:8080/api/logs
```

## Troubleshooting

### Services not starting
```bash
# Check logs
docker-compose logs [service-name]

# Restart a specific service
docker-compose restart [service-name]

# Rebuild and restart
docker-compose up -d --build [service-name]
```

### Database connection issues
- Ensure PostgreSQL is healthy: `docker-compose ps postgres`
- Check database exists: `docker-compose exec postgres psql -U postgres -l`

### Frontend can't reach backend
- Frontend runs in Docker, so it uses `proxy-backend:8080` internally
- Vite proxy is configured to route `/api` to backend
- If running frontend locally, it will use `http://localhost:8080`

## Development Workflow

### Option 1: Everything in Docker
```bash
docker-compose up -d
# Access frontend at http://localhost:5173
```

### Option 2: Backend in Docker, Frontend Local
```bash
# Start backend services
docker-compose up -d postgres billions-mock erigon-mock proxy-backend

# Run frontend locally
cd frontend && npm run dev
```

### Option 3: Everything Local
```bash
# Start only mocks and database
docker-compose up -d postgres billions-mock erigon-mock

# Run backend locally
make dev

# Run frontend locally
cd frontend && npm run dev
```
