# Testbed Architecture

## Overview

The privacy proxy testbed supports two testing modes:

1. **Unit/Integration Tests (Go)**: Use mock servers for fast, deterministic testing
2. **E2E Tests (Playwright)**: Use real Anvil node for comprehensive API testing

**Key Design Decisions:**
- Mock Ethereum node for fast unit/integration tests
- Anvil (Foundry) for realistic E2E tests
- Mock Billions service always returns KYC=true
- testcontainers-go for automatic PostgreSQL in unit tests
- Docker Compose for full E2E testing
- Playwright for parallel API test execution

---

## Docker Compose Services

**File:** `docker-compose.yml`

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `postgres` | postgres:15-alpine | 5432 | Policy and token storage |
| `erigon-mock` | node:20-alpine | 8545 | Mock Ethereum JSON-RPC node |
| `billions-mock` | node:20-alpine | 9000 | Mock KYC/identity service |
| `proxy-backend` | Go binary | 8080 | Privacy proxy server |
| `proxy-frontend` | Node.js | 5173 | Admin UI (Vite dev server) |

### Service Dependencies

```
postgres ──┐
            ├──▶ proxy-backend ──▶ proxy-frontend
erigon-mock ┤
            │
billions-mock ┘
```

All services wait for their dependencies to be healthy before starting.

---

## Mock Ethereum Node

**Location:** `e2e/mock-node/server.js`

A minimal Express.js server that responds to JSON-RPC requests with hardcoded values.

### Supported Methods

```javascript
const mockResponses = {
  'eth_call': {
    jsonrpc: '2.0',
    result: '0x0000000000000000000000000000000000000000000000000000000000000001',
    id: null,
  },
  'eth_getBalance': {
    jsonrpc: '2.0',
    result: '0x2386f26fc10000',  // 0.01 ETH
    id: null,
  },
  'eth_blockNumber': {
    jsonrpc: '2.0',
    result: '0x123456',
    id: null,
  },
};
```

### Behavior

- **Known methods:** Return mock response with request ID
- **Unknown methods:** Return JSON-RPC error `-32601 Method not found`
- **Health check:** `GET /health` returns `{"status": "ok"}`

### Adding New Mock Methods

Edit `e2e/mock-node/server.js`:

```javascript
const mockResponses = {
  // ... existing methods ...
  'eth_chainId': {
    jsonrpc: '2.0',
    result: '0x1',  // Mainnet
    id: null,
  },
};
```

---

## Mock Billions Service

**Location:** `e2e/mock-billions/server.js`

A minimal Express.js server that simulates the Billions KYC API.

### API Endpoint

```
GET /verify
Headers: Authorization: Bearer {user_id}

Response:
{
  "subject": "billions:{user_id}",
  "kyc": true,
  "claims": {
    "token": "{user_id}",
    "iat": <unix_timestamp>,
    "exp": <unix_timestamp + 3600>
  }
}
```

### Behavior

- **Valid token:** Returns identity with `kyc: true`
- **Missing/empty token:** Returns 401 error
- **Health check:** `GET /health` returns `{"status": "ok"}`

### Testing KYC Failures

The mock always returns `kyc: true`. To test KYC failures, create a policy with `kyc: false` in the database - the access controller checks the policy's KYC flag, not the Billions response.

---

## Unit Tests with testcontainers-go

**Location:** `internal/db/test_helper.go`

Unit tests use testcontainers-go to automatically spin up PostgreSQL containers. No manual database setup required.

### How It Works

```go
// internal/db/test_helper.go:86-142
func SetupTestContainer(t *testing.T) (string, func()) {
    // Try to start PostgreSQL container
    postgresContainer, err := postgres.RunContainer(ctx,
        testcontainers.WithImage("postgres:15-alpine"),
        postgres.WithDatabase("testdb"),
        postgres.WithUsername("testuser"),
        postgres.WithPassword("testpass"),
        // ...
    )

    // If Docker unavailable, fall back to external PostgreSQL
    if err != nil {
        dbURL := "postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
        return dbURL, func() {}
    }

    return connStr, cleanup
}
```

### Fallback Behavior

If testcontainers fails (Docker not available, network issues):
1. Falls back to external PostgreSQL at `localhost:5432`
2. Creates `privacy_proxy_test` database if needed
3. Uses `TEST_DATABASE_URL` environment variable if set

---

## E2E Tests

**Location:** `e2e/proxy_test.go`

End-to-end tests that verify the full authentication and authorization flow.

### Test Setup

```go
// e2e/proxy_test.go:49-130
func setupE2EWithVerifier(t *testing.T, verifier server.PrivadoVerifier) (*server.Server, string, func()) {
    // 1. Get database (testcontainers or fallback)
    dbURL, cleanupDB := db.SetupTestContainer(t)

    // 2. Find available port
    listener, _ := net.Listen("tcp", ":0")
    port := listener.Addr().(*net.TCPAddr).Port

    // 3. Configure server
    cfg := &config.Config{
        NodeURL:     "http://localhost:8545",
        DatabaseURL: dbURL,
        // ...
    }

    // 4. Start server with mock verifier
    srv := server.NewWithVerifier(cfg, verifier)
    go srv.Run(serverAddr)

    // 5. Wait for server to be ready
    // ... health check polling ...

    return srv, serverURL, cleanup
}
```

### Mock Privado Verifier

Tests use a mock Privado verifier to avoid real ZK proof verification:

```go
// e2e/proxy_test.go:23-47
type mockPrivadoVerifier struct {
    userDID string
}

func (m *mockPrivadoVerifier) VerifyJWZ(...) (string, error) {
    return m.userDID, nil  // Always succeeds with configured DID
}
```

### Test Cases

| Test | Description |
|------|-------------|
| `TestE2E_AuthorizedRequest` | User with valid policy can make allowed calls |
| `TestE2E_UnauthorizedRequest_NoToken` | Request without JWT returns 401 |
| `TestE2E_ForbiddenRequest_DisallowedMethod` | Calling non-whitelisted method returns 403 |
| `TestE2E_BannedUser` | Banned user returns 403 |
| `TestE2E_NoKYC` | User without KYC returns 403 |

---

---

## Playwright E2E Tests

**Location:** `e2e/playwright/`

Playwright-based E2E tests run against a real Docker environment with Anvil.

### Directory Structure

```
e2e/playwright/
├── package.json           # Dependencies
├── playwright.config.ts   # Test configuration
├── tsconfig.json          # TypeScript config
├── Dockerfile             # Test runner container
├── global-setup.ts        # Wait for services
├── helpers/
│   ├── auth.ts            # JWT token acquisition
│   ├── policy.ts          # Policy CRUD via admin API
│   └── test-context.ts    # Test isolation (unique DIDs)
└── tests/
    ├── authorization.spec.ts   # Deny unauthenticated
    ├── access-control.spec.ts  # Policy-based access
    ├── multicall.spec.ts       # Multicall blocking
    └── auth-formats.spec.ts    # QR/deeplink tests
```

### Test Isolation

Each test gets a unique DID using `TestContext`:

```typescript
test('my test', async ({ request }) => {
  const ctx = new TestContext();
  // ctx.userDID = 'did:privado:test_a1b2c3d4'

  await ctx.createPolicy(request, { kyc: true });
  const token = await ctx.getToken(request);
  // Use token for API requests...

  await ctx.cleanup(request);
});
```

### Docker Compose Override

The `docker-compose.e2e.yml` file overrides the base config to:
- Replace mock node with Anvil (real Ethereum node)
- Add Playwright test runner service
- Disable frontend (not needed for API tests)

### Running Playwright Tests

```bash
# Run full E2E suite (starts services, runs tests, stops services)
make e2e

# Debug mode (services stay running)
make e2e-debug

# Stop E2E services
make e2e-down
```

### Test Reports

After running tests:
- HTML report: `e2e/playwright/playwright-report/index.html`
- JUnit XML: `e2e/playwright/test-results/junit.xml`

---

## Running Tests

### Unit Tests

```bash
# Run all unit tests (auto-starts PostgreSQL container)
make test-unit

# Or directly:
go test ./internal/...
```

### E2E Tests

```bash
# Run E2E tests (requires Docker for testcontainers)
make test-e2e

# Or directly:
go test ./e2e/...

# With external PostgreSQL (for CI):
export TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/test?sslmode=disable"
go test ./e2e/...
```

### Full Docker Environment

```bash
# Start all services
make docker-up

# Or directly:
docker-compose up -d

# View logs
docker-compose logs -f proxy-backend

# Stop all services
make docker-down
```

### Service URLs When Running Docker

| Service | URL |
|---------|-----|
| Privacy Proxy API | http://localhost:8080 |
| Admin UI | http://localhost:5173 |
| Mock Ethereum Node | http://localhost:8545 |
| Mock Billions | http://localhost:9000 |
| PostgreSQL | localhost:5432 |

---

## Writing New E2E Tests

### Basic Template

```go
func TestE2E_MyFeature(t *testing.T) {
    userDID := "did:privado:test_user"

    // Setup server with mock verifier
    mockVerifier := &mockPrivadoVerifier{userDID: userDID}
    srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
    defer cleanup()

    // Get database and reset tables
    database := srv.DB()
    database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
    database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
    database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
    database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
    database.Migrate()

    // Create policy for user
    policy := &db.AccessPolicy{
        ExternalID:   userDID,
        KYC:          true,
        AllowMethods: []string{"eth_call"},
        Banned:       false,
    }
    database.SetPolicy(policy)

    // Get JWT token
    accessToken := getJWTToken(t, serverURL, userDID)

    // Make request
    reqBody := map[string]interface{}{
        "jsonrpc": "2.0",
        "method":  "eth_call",
        "params":  []interface{}{},
        "id":      1,
    }
    jsonBody, _ := json.Marshal(reqBody)

    req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        t.Fatalf("request failed: %v", err)
    }
    defer resp.Body.Close()

    // Assert response
    if resp.StatusCode != http.StatusOK {
        t.Errorf("expected 200, got %d", resp.StatusCode)
    }
}
```

### Testing with Mock Node

If your test needs specific responses from the Ethereum node, either:

1. **Use existing mocks:** The mock node already supports `eth_call`, `eth_getBalance`, `eth_blockNumber`

2. **Add new mocks:** Edit `e2e/mock-node/server.js` to add responses

3. **Use Docker Compose:** Start the full environment and the mock node will be available at `http://localhost:8545`

---

## CI Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run tests
        env:
          TEST_DATABASE_URL: postgres://postgres:postgres@localhost:5432/test?sslmode=disable
        run: |
          go test ./internal/...
          go test ./e2e/...
```

---

## Troubleshooting

### Docker Issues

```bash
# Check if containers are running
docker-compose ps

# View container logs
docker-compose logs postgres
docker-compose logs erigon-mock

# Restart a specific service
docker-compose restart proxy-backend
```

### Database Issues

```bash
# Connect to database
docker-compose exec postgres psql -U postgres -d privacy_proxy

# Reset database
docker-compose down -v
docker-compose up -d
```

### Test Failures

```bash
# Run with verbose output
go test -v ./e2e/...

# Run specific test
go test -v -run TestE2E_AuthorizedRequest ./e2e/...
```

---

## Code References

| File | Lines | Description |
|------|-------|-------------|
| `docker-compose.yml` | 1-112 | Service definitions |
| `e2e/mock-node/server.js` | 1-54 | Mock Ethereum node |
| `e2e/mock-billions/server.js` | 1-61 | Mock Billions service |
| `e2e/proxy_test.go` | 49-130 | E2E test setup |
| `internal/db/test_helper.go` | 86-142 | testcontainers setup |
