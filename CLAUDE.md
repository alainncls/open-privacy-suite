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

## Running Services

See README.md for full documentation. Quick reference:

```bash
# Start privacy-proxy
docker-compose up -d

# Start explorer (privacy-proxy must be running first)
docker-compose -f ../explorer/docker-compose.privacy-proxy.yml up -d
```

**Note:** For network access from other devices, see `DEV.local.md` (gitignored) for machine-specific setup.

## Documentation Site

The docs site lives in `site/` (Next.js + MDX). When changing auth, RBAC, security, compliance, or other user-facing logic, update the corresponding docs page in `site/src/app/docs/`. Docs should be updated in the same PR as the code change.
