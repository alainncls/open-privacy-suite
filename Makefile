.PHONY: build test test-unit test-e2e run run-binary dev clean clean-build e2e e2e-debug e2e-down e2e-clean \
	db-migrate db-status db-new-migration install-tern seed \
	contracts-install contracts-build contracts-deploy authproxy \
	stop restart logs status \
	demo demo-record demo-process demo-all demo-setup demo-clean \
	setup-hooks ensure-hooks

# Auto-install hooks on first make usage
HOOKS_MARKER := .git/.hooks-installed
$(HOOKS_MARKER):
	@./scripts/setup-hooks.sh
	@touch $(HOOKS_MARKER)

ensure-hooks: $(HOOKS_MARKER)

# Build backend
build: ensure-hooks
	go build -o bin/privacy-proxy ./cmd/server

# Build authproxy
authproxy: ensure-hooks
	go build -o bin/authproxy ./cmd/authproxy

# Run full Docker stack (postgres, anvil, backend, frontend)
run: ensure-hooks
	docker-compose up --build -d

# Stop all services
stop:
	docker-compose down

# Restart all services
restart:
	docker-compose down && docker-compose up --build -d

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

# Run all tests (Go + Frontend)
test: ensure-hooks test-unit frontend-test

# Run Go tests
test-go:
	go test ./... -v

# Run unit tests only (with -p 1 to avoid database conflicts between packages)
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
	@docker-compose ps postgres 2>/dev/null | grep -q "Up" || (echo "PostgreSQL is not running. Starting it..." && docker-compose up -d postgres && sleep 2)
	@echo "PostgreSQL is ready"

# Run Go E2E tests
test-e2e:
	go test ./e2e/... -v -p 1

# E2E compose command - isolated from local dev
E2E_COMPOSE = docker-compose -p privacy-proxy-e2e -f docker-compose.e2e.yml

# Run Playwright E2E tests with Docker Compose (isolated environment)
e2e: ensure-hooks
	$(E2E_COMPOSE) up -d --build postgres anvil proxy-backend
	$(E2E_COMPOSE) run --rm playwright npm test; \
	status=$$?; \
	$(E2E_COMPOSE) down -v; \
	exit $$status

# Run Playwright E2E tests and keep services running (for debugging)
e2e-debug:
	$(E2E_COMPOSE) up -d --build postgres anvil proxy-backend
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

# Run frontend tests
frontend-test:
	cd frontend && npm run test:run

# Run frontend tests with coverage
frontend-test-coverage:
	cd frontend && npm run test:coverage

# Run all tests (Go + Frontend)
test-all: test-unit frontend-test

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
# Requires: Anvil running on localhost:8545 (use 'make run' to start all services)
# Uses Anvil's default account 0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
contracts-deploy:
	@echo "Deploying Counter contract to local Anvil..."
	@echo "Make sure Anvil is running (docker-compose up anvil)"
	cd contracts && forge script script/Deploy.s.sol:DeployCounter \
		--rpc-url http://localhost:8545 \
		--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
		--broadcast
	@echo ""
	@echo "Contract deployed! Add the address above to the admin UI contracts section."

# Deploy and show contract address (quieter output)
contracts-deploy-quiet:
	@cd contracts && forge script script/Deploy.s.sol:DeployCounter \
		--rpc-url http://localhost:8545 \
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
