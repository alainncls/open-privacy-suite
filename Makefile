.PHONY: build test test-unit test-e2e run dev clean

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

# Run E2E tests
test-e2e:
	go test ./e2e/... -v

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

# Setup database
db-migrate:
	go run ./cmd/migrate

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
