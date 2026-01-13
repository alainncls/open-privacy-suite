# Testing Guide

## Prerequisites

**Good news**: Tests now use **testcontainers** by default! No need to start PostgreSQL manually.

Tests automatically spin up a PostgreSQL container in Docker, run the tests, and clean up. Just make sure Docker is running.

### Option 1: Automatic (Recommended - Default)

Tests use **testcontainers-go** which automatically:
- Spins up a PostgreSQL container for each test run
- Runs migrations
- Executes tests
- Cleans up the container when done

**No setup needed!** Just run:

```bash
go test ./internal/... -v
```

### Option 2: External PostgreSQL (For CI or explicit control)

If you set `TEST_DATABASE_URL`, tests will use that instead of testcontainers:

If you prefer to use an external PostgreSQL instance (e.g., for CI/CD):

```bash
export TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
go test ./internal/... -v
```

Or start PostgreSQL with Docker Compose:

```bash
docker-compose up -d postgres
export TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
go test ./internal/... -v
```

## Running Tests

### Unit Tests

**Business Logic Tests (No Database Required):**
```bash
# Access control tests use mocks - no PostgreSQL needed
go test ./internal/access/... -v

# JWT and middleware tests - no database needed
go test ./internal/auth/... -v
```

**Database Layer Tests (Uses Testcontainers):**
```bash
# Database tests use real PostgreSQL via testcontainers
go test ./internal/db/... -v
```

**All Unit Tests:**
```bash
make test-unit
# or
go test ./internal/... -v
```

**Note**: 
- Business logic tests (`access`, `auth`) use mocks - **no PostgreSQL needed**
- Database layer tests (`db`) use testcontainers - **Docker required**
- Server tests use real database for integration testing

### E2E Tests

For E2E tests, you also need the mock services:

```bash
docker-compose up -d postgres erigon-mock
make test-e2e
# or
go test ./e2e/... -v
```

### All Tests

```bash
make test
# or
go test ./... -v
```

## How It Works

### Testcontainers (Default)

When `TEST_DATABASE_URL` is not set:
1. Testcontainers spins up a fresh PostgreSQL 15 container
2. Each test package gets its own isolated database
3. Tests run with clean state
4. Container is automatically terminated after tests

**Benefits:**
- ✅ No manual setup required
- ✅ Isolated test environments
- ✅ Works the same on all machines
- ✅ No shared state between test runs

### External PostgreSQL (When `TEST_DATABASE_URL` is set)

When you set `TEST_DATABASE_URL`:
- Tests use the provided PostgreSQL instance
- Useful for CI/CD pipelines with managed databases
- Requires manual database creation

## Troubleshooting

### "Docker not running" Error

If you see Docker-related errors, make sure Docker is running:

```bash
# Check Docker status
docker ps

# Start Docker Desktop (macOS/Windows) or Docker daemon (Linux)
```

### "failed to start postgres container" Error

This usually means:
- Docker is not running
- Docker doesn't have enough resources
- Network issues

**Solution**: 
1. Ensure Docker is running: `docker ps`
2. Check Docker resources (memory/CPU)
3. Try: `docker system prune` to free up space

### Using External PostgreSQL

If you prefer external PostgreSQL and see connection errors:

```bash
# Start PostgreSQL
docker-compose up -d postgres

# Set environment variable
export TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"

# Create database
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE privacy_proxy_test;"

# Run tests
go test ./internal/... -v
```

### Using Custom Database URL

Set the `TEST_DATABASE_URL` environment variable:

```bash
export TEST_DATABASE_URL="postgres://user:pass@host:port/dbname?sslmode=disable"
go test ./internal/... -v
```

## Test Coverage

To see test coverage:

```bash
go test ./internal/... -cover
```

For detailed coverage report:

```bash
go test ./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```
