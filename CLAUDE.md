# Privacy Proxy - Project Conventions

## Database

### PostgreSQL Access
- Use **pgx v5** (`github.com/jackc/pgx/v5`) for PostgreSQL connections
- Use `database/sql` with pgx stdlib driver for standard SQL interface
- Connection pooling handled by `database/sql`

### Migrations with Tern
- Use **tern v2** (`github.com/jackc/tern/v2`) for database migrations
- Migrations stored in `internal/db/migrations/*.sql`
- Embedded via Go embed in `internal/db/migrations/migrations.go`

#### Creating New Migrations
```bash
make db-new-migration name=add_user_preferences
```

#### Running Migrations
```bash
make db-migrate
```

### Expand-Only Migration Policy

**Production migrations must be additive only (expand-only):**

- `CREATE TABLE`, `ADD COLUMN`, `CREATE INDEX`, `ALTER TABLE ... ADD CONSTRAINT` - allowed
- `DROP TABLE`, `DROP COLUMN`, `DROP INDEX`, `ALTER TABLE ... DROP CONSTRAINT` - never in production

**DOWN migrations** are optional (development only). If a migration needs undoing in production, create a new forward migration.

## Testing

```bash
make test-unit   # Go unit tests
make e2e         # End-to-end tests
```

## Code Style

- Go: idiomatic, explicit error handling, table-driven tests
- Follow `gofmt` for formatting
