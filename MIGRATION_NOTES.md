# Migration from SQLite to PostgreSQL

## Changes Made

### 1. Dependencies
- **Removed**: `github.com/mattn/go-sqlite3`
- **Added**: `github.com/jackc/pgx/v5` (PostgreSQL driver)

### 2. Configuration
- **Changed**: `DBPath` → `DatabaseURL`
- **Default**: `postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable`

### 3. Database Schema Changes
- `TEXT` → `VARCHAR(255)` for string fields
- `INTEGER` → `BOOLEAN` for boolean fields
- `TEXT` → `JSONB` for JSON fields (PostgreSQL native JSON support)
- `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
- `DATETIME` → `TIMESTAMP`
- Placeholder syntax: `?` → `$1, $2, ...` (PostgreSQL parameterized queries)

### 4. Connection
- Uses `pgx` driver via `database/sql` interface
- Connection string format: `postgres://user:password@host:port/database?sslmode=disable`

### 5. Testing
- Tests now use PostgreSQL connection strings
- Set `TEST_DATABASE_URL` environment variable for custom test database
- Default test database: `privacy_proxy_test`

### 6. Docker Compose
- Added PostgreSQL service
- Backend depends on PostgreSQL health check
- Database persists in Docker volume

## Migration Steps

1. **Install PostgreSQL** (if not using Docker):
   ```bash
   # macOS
   brew install postgresql
   brew services start postgresql
   
   # Linux
   sudo apt-get install postgresql
   sudo systemctl start postgresql
   ```

2. **Create Database**:
   ```bash
   createdb privacy_proxy
   ```

3. **Update Environment**:
   ```bash
   export DATABASE_URL="postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"
   ```

4. **Run Migrations**:
   ```bash
   go run ./cmd/migrate
   ```

5. **Or Use Docker Compose**:
   ```bash
   docker-compose up -d postgres
   # Wait for health check, then:
   docker-compose up proxy-backend
   ```

## Benefits

- **Better Performance**: PostgreSQL handles concurrent connections better
- **JSON Support**: Native JSONB type for better querying
- **Production Ready**: PostgreSQL is standard for production deployments
- **Better Tooling**: Rich ecosystem of PostgreSQL tools and extensions
- **Scalability**: Better suited for high-traffic scenarios
