.PHONY: build build-prod test test-unit test-e2e test-privacy-bypass run dev-stack run-binary clean clean-build e2e e2e-debug e2e-down e2e-clean \
	db-migrate db-status db-new-migration install-tern seed \
	contracts-install contracts-build contracts-deploy authproxy \
	stop restart logs status \
	demo demo-record demo-process demo-all demo-setup demo-clean \
	setup-hooks ensure-hooks

# Auto-install hooks on first make usage (works in worktrees where .git is a file)
GIT_DIR := $(shell git rev-parse --git-dir)
HOOKS_MARKER := $(GIT_DIR)/.hooks-installed
$(HOOKS_MARKER):
	@./scripts/setup-hooks.sh
	@touch $(HOOKS_MARKER)

ensure-hooks: $(HOOKS_MARKER)

# Build backend (dev, with mock auth)
build: ensure-hooks
	go build -tags mockauth -o bin/privacy-proxy ./cmd/server

# Build production Docker image (no mock auth, no dev shortcuts)
build-prod: ensure-hooks
	docker build -f Dockerfile.backend --target prod -t privacy-proxy:prod .

# Build authproxy
authproxy: ensure-hooks
	go build -o bin/authproxy ./cmd/authproxy

# Run full Docker stack (postgres, anvil, backend, frontend)
run: ensure-hooks
	docker-compose up --build -d
	@./scripts/print-urls.sh

# Start an isolated dev stack — auto-assigns offset ports so parallel stacks don't conflict.
# If REDIS_URL is set in .env or the environment, the built-in Redis is skipped
# and the backend connects to the external Redis instance.
dev-stack: ensure-hooks
	@if [ ! -f .env ] && [ "$$(basename "$$(pwd)")" != "privacy-proxy" ]; then \
		./scripts/stack-ports.sh auto > .env; \
		echo "Generated .env with offset ports (worktree detected)"; \
	fi
	@if grep -q '^REDIS_URL=' .env 2>/dev/null || [ -n "$${REDIS_URL}" ]; then \
		echo "External REDIS_URL detected — skipping built-in Redis"; \
		docker-compose up --build -d postgres anvil proxy-backend proxy-frontend; \
	else \
		docker-compose up --build -d; \
	fi
	@./scripts/print-urls.sh

# Stop all services
stop:
	docker-compose down

# Restart all services
restart:
	docker-compose down && docker-compose up --build -d
	@./scripts/print-urls.sh

# View logs
logs:
	docker-compose logs -f

# Show service status
status:
	docker-compose ps

# Run backend binary directly (without Docker)
run-binary: build
	./bin/privacy-proxy

# Run in dev mode (with hot reload)
dev: ensure-hooks
	go run ./cmd/server

# Run all tests (Go unit + Go e2e + Frontend)
test: ensure-hooks test-go frontend-test

# Run all Go tests (unit + e2e)
test-go: test-unit test-e2e

# Run Go unit tests only (with -p 1 to avoid database conflicts between packages)
test-unit: test-db-ready
	go test ./internal/... -v -p 1

# Minimum coverage threshold (percentage) - start at 45%, increase over time
MIN_COVERAGE ?= 45

# Run unit tests with coverage
test-coverage: test-db-ready
	go test ./internal/... -v -p 1 -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run unit tests with coverage and enforce minimum threshold
test-coverage-check: test-db-ready
	go test ./internal/... -v -p 1 -coverprofile=coverage.out
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	COVERAGE_INT=$${COVERAGE%.*}; \
	echo "Total coverage: $${COVERAGE}%"; \
	if [ "$$COVERAGE_INT" -lt "$(MIN_COVERAGE)" ]; then \
		echo "ERROR: Coverage $${COVERAGE}% is below minimum threshold of $(MIN_COVERAGE)%"; \
		exit 1; \
	fi; \
	echo "Coverage $${COVERAGE}% meets minimum threshold of $(MIN_COVERAGE)%"

# Check if test database is ready
test-db-ready:
	@echo "Checking PostgreSQL connection..."
	@docker-compose ps postgres | grep -q "Up" || (echo "PostgreSQL is not running. Starting it..." && docker-compose up -d postgres && sleep 2)
	@echo "PostgreSQL is ready"

# Run Go E2E tests
test-e2e: test-db-ready
	go test ./e2e/... -v -p 1

# Negative-network test for the privacy-mode deployment (RD-855 Phase 4b).
# Brings up docker-compose.privacy.yml (nine services) and verifies the
# trust boundary is closed: trust-zone services unreachable from the
# host, frontend routes correctly, /ws returns 404. Takes 1-2 minutes;
# build-tag gated so it doesn't run in default test runs or the
# pre-push hook. Expects chain-indexer + block-explorer cloned as
# siblings of privacy-proxy.
test-privacy-bypass:
	JWT_SECRET=test-jwt-secret-do-not-use-in-production-1234567890 \
	JWT_REFRESH_SECRET=test-refresh-secret-do-not-use-in-production-0987654321 \
	ADMIN_API_TOKEN=test-admin-token \
	go test -tags privacy_bypass -timeout 10m -v -run TestPrivacyModeBypassClosure ./e2e/...

# E2E compose command - isolated from local dev
E2E_COMPOSE = docker-compose -p privacy-proxy-e2e -f docker-compose.e2e.yml

# Run Playwright E2E tests with Docker Compose (isolated environment)
e2e: ensure-hooks
	$(E2E_COMPOSE) up -d --build postgres anvil proxy-backend proxy-frontend
	$(E2E_COMPOSE) run --rm playwright npm test; \
	status=$$?; \
	$(E2E_COMPOSE) down -v; \
	exit $$status

# Run Playwright E2E tests and keep services running (for debugging)
e2e-debug:
	$(E2E_COMPOSE) up -d --build postgres anvil proxy-backend proxy-frontend
	$(E2E_COMPOSE) run --rm playwright npm run test:debug
	@echo "Services still running. Run 'make e2e-down' to stop them."

# Stop E2E services and clean up volumes
e2e-down:
	$(E2E_COMPOSE) down -v

# Force clean E2E environment (removes containers, volumes, networks)
e2e-clean:
	$(E2E_COMPOSE) down -v --remove-orphans
	@docker volume rm privacy-proxy-e2e_e2e-postgres-data 2>/dev/null || true

# Install frontend dependencies
frontend-install:
	cd frontend && npm install

# Run frontend dev server
frontend-dev:
	cd frontend && npm run dev

# Build frontend
frontend-build:
	cd frontend && npm run build

# Run frontend tests (auto-install if node_modules missing)
frontend-test:
	@test -x frontend/node_modules/.bin/vitest || (echo "Installing frontend dependencies..." && cd frontend && npm install)
	cd frontend && npm run test:run

# Run frontend tests with coverage
frontend-test-coverage:
	cd frontend && npm run test:coverage

# Alias for 'test'
test-all: test

# Clean Docker environment (stop services, remove volumes)
clean:
	docker-compose down -v
	docker system prune -f

# Clean build artifacts
clean-build:
	rm -rf bin/
	rm -rf frontend/dist/
	rm -rf frontend/node_modules/
	go clean

# Run database migrations (via Go - uses embedded migrations)
db-migrate:
	go run ./cmd/migrate

# Show migration status using tern CLI
db-status:
	@tern status -c tern.conf -m internal/db/migrations 2>/dev/null || \
		echo "Run 'make install-tern' to install tern CLI, or use 'make db-migrate' for Go-based migrations"

# Create a new migration file
# Usage: make db-new-migration name=add_user_table
db-new-migration:
	@if [ -z "$(name)" ]; then \
		echo "Usage: make db-new-migration name=migration_name"; \
		exit 1; \
	fi
	@next=$$(ls internal/db/migrations/*.sql 2>/dev/null | wc -l | tr -d ' '); \
	next=$$((next + 1)); \
	filename=$$(printf "%03d_%s.sql" $$next "$(name)"); \
	echo "-- $(name)" > "internal/db/migrations/$$filename"; \
	echo "" >> "internal/db/migrations/$$filename"; \
	echo "---- create above / drop below ----" >> "internal/db/migrations/$$filename"; \
	echo "" >> "internal/db/migrations/$$filename"; \
	echo "-- Optional: down migration" >> "internal/db/migrations/$$filename"; \
	echo "Created: internal/db/migrations/$$filename"

# Install tern CLI tool
install-tern:
	go install github.com/jackc/tern/v2@latest
	@echo "tern installed. Ensure \$$GOPATH/bin is in your PATH."

# Setup test databases
test-db-setup:
	./scripts/setup-test-db.sh

# Seed database with development data
seed:
	@echo "Seeding database with development data..."
	@docker-compose exec -T postgres psql -U postgres -d privacy_proxy < scripts/seed.sql
	@echo "Done!"

# ============================================================================
# Documentation Site
# ============================================================================

# Run docs site in development mode
site-dev:
	cd site && npm run dev

# Build docs site for production (static export)
site-build:
	cd site && npm run build

# Install docs site dependencies
site-install:
	cd site && npm install

# ============================================================================
# Contract Development (Foundry)
# ============================================================================

# Install Foundry dependencies (forge-std)
contracts-install:
	@echo "Installing Foundry dependencies..."
	cd contracts && forge install foundry-rs/forge-std --no-commit
	@echo "Done!"

# Build contracts
contracts-build:
	@echo "Building contracts..."
	cd contracts && forge build
	@echo "Done!"

# Deploy Counter contract to local Anvil
# Requires: Anvil running (use 'make run' to start all services)
# Uses Anvil's default account 0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
RPC_URL ?= http://localhost:$(or $(HOST_PORT_RPC),8545)

contracts-deploy:
	@echo "Deploying Counter contract to local Anvil..."
	@echo "Make sure Anvil is running (docker-compose up anvil)"
	cd contracts && forge script script/Deploy.s.sol:DeployCounter \
		--rpc-url $(RPC_URL) \
		--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
		--broadcast
	@echo ""
	@echo "Contract deployed! Add the address above to the admin UI contracts section."

# Deploy and show contract address (quieter output)
contracts-deploy-quiet:
	@cd contracts && forge script script/Deploy.s.sol:DeployCounter \
		--rpc-url $(RPC_URL) \
		--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
		--broadcast 2>&1 | grep -E "(Counter deployed to:|deployed)"

# ============================================================================
# Demo Video Generation
# ============================================================================

# Setup demo generation environment
demo-setup:
	@cd demos && make setup

# Generate complete demo video
# Usage: make demo name=auth-flow
demo:
	@cd demos && make demo name=$(name)

# Record video only (no processing)
# Usage: make demo-record name=auth-flow
demo-record:
	@cd demos && make demo-record name=$(name)

# Process existing recording
# Usage: make demo-process name=auth-flow
demo-process:
	@cd demos && make demo-process name=$(name)

# Generate all demo videos
demo-all:
	@cd demos && make demo-all

# List available demo configurations
demo-list:
	@cd demos && make demo-list

# Clean demo outputs
demo-clean:
	@cd demos && make clean

# ============================================================================
# Git Hooks
# ============================================================================

# Setup git hooks (run once after cloning)
setup-hooks:
	@./scripts/setup-hooks.sh

## proto-gen: Regenerate Go stubs from vendored chain-indexer .proto files.
##            We do NOT depend on chain-indexer's Go module — we carry our
##            own copy of the .proto contract and build stubs here. When
##            chain-indexer's proto surface changes, copy updated files
##            from chain-indexer/proto/chain_indexer/v1/*.proto and re-run.
.PHONY: proto-gen
proto-gen:
	@which buf > /dev/null || (echo "buf not installed: https://buf.build/docs/installation"; exit 1)
	buf generate

## proto-lint: Lint vendored .proto files.
.PHONY: proto-lint
proto-lint:
	@which buf > /dev/null || (echo "buf not installed"; exit 1)
	buf lint
