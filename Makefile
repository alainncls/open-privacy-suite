.PHONY: build test test-unit test-e2e run dev clean e2e e2e-debug e2e-down \
	db-migrate db-status db-new-migration install-tern

# Build backend
build:
	go build -o bin/privacy-proxy ./cmd/server

# Run backend
run: build
	./bin/privacy-proxy

# Run in dev mode (with hot reload)
dev:
	go run ./cmd/server

# Run all tests
test:
	go test ./... -v

# Run unit tests only
test-unit: test-db-ready
	go test ./internal/... -v

# Check if test database is ready
test-db-ready:
	@echo "Checking PostgreSQL connection..."
	@docker-compose ps postgres | grep -q "Up" || (echo "PostgreSQL is not running. Starting it..." && docker-compose up -d postgres && sleep 2)
	@echo "PostgreSQL is ready"

# Run Go E2E tests
test-e2e:
	go test ./e2e/... -v

# Run Playwright E2E tests with Docker Compose
e2e:
	docker-compose -f docker-compose.yml -f docker-compose.e2e.yml up -d --build postgres billions-mock anvil proxy-backend
	docker-compose -f docker-compose.yml -f docker-compose.e2e.yml run --rm playwright npm test
	docker-compose -f docker-compose.yml -f docker-compose.e2e.yml down

# Run Playwright E2E tests and keep services running (for debugging)
e2e-debug:
	docker-compose -f docker-compose.yml -f docker-compose.e2e.yml up -d --build postgres billions-mock anvil proxy-backend
	docker-compose -f docker-compose.yml -f docker-compose.e2e.yml run --rm playwright npm run test:debug
	@echo "Services still running. Run 'make e2e-down' to stop them."

# Stop E2E services
e2e-down:
	docker-compose -f docker-compose.yml -f docker-compose.e2e.yml down

# Install frontend dependencies
frontend-install:
	cd frontend && npm install

# Run frontend dev server
frontend-dev:
	cd frontend && npm run dev

# Build frontend
frontend-build:
	cd frontend && npm run build

# Clean build artifacts
clean:
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

# Docker compose up
docker-up:
	docker-compose up -d

# Docker compose up with logs
docker-up-logs:
	docker-compose up

# Docker compose down
docker-down:
	docker-compose down

# Docker compose down with volumes
docker-down-clean:
	docker-compose down -v

# View logs
docker-logs:
	docker-compose logs -f
