# Privacy Proxy - Project Conventions

## Persistent Task Tracking (TODO.md)

**Read `TODO.md` at the start of each session** to understand current priorities and context.

### Workflow
1. **On session start**: Read TODO.md to see active tasks, blockers, and context
2. **During work**: Update TODO.md as you complete items or discover new issues
3. **Before ending**: Ensure TODO.md reflects current state for continuity

### TODO.md Format
```markdown
# TODO

## In Progress
- [ ] Task description with relevant context

## Blocked
- [ ] Task - **Blocker:** reason

## Backlog
- [ ] Future task

## Done (Recent)
- [x] Completed task - brief outcome/notes
```

### Guidelines
- Keep entries concise but include enough context for future sessions
- Move completed items to "Done (Recent)" with outcome notes
- Periodically archive old "Done" items to keep the file manageable
- Both human and AI can add/update items freely

---

## Database

### PostgreSQL Access
- Use **pgx v5** (`github.com/jackc/pgx/v5`) for PostgreSQL connections
- Use `database/sql` with pgx stdlib driver for standard SQL interface
- Connection pooling handled by `database/sql`

### Migrations with Tern
- Use **tern v2** (`github.com/jackc/tern/v2`) for database migrations
- Migrations stored in `internal/db/migrations/*.sql`
- Embedded via Go embed in `internal/db/migrations/migrations.go`

#### Migration File Format
```sql
-- Write your migrate up statements here

---- create above / drop below ----

-- Write your migrate down statements here (optional)
```

#### Creating New Migrations
```bash
make db-new-migration name=add_user_preferences
```

This creates a new file like `003_add_user_preferences.sql`.

#### Running Migrations
```bash
# Via Go (preferred - uses embedded migrations)
make db-migrate

# Via tern CLI (requires DATABASE_URL or PG* env vars)
tern migrate -c tern.conf -m internal/db/migrations
```

### Expand-Only Migration Policy

**Production migrations must be additive only (expand-only):**

✅ **Allowed in UP migrations:**
- `CREATE TABLE`
- `ADD COLUMN`
- `CREATE INDEX`
- `ALTER TABLE ... ADD CONSTRAINT`

❌ **Never in production UP migrations:**
- `DROP TABLE`
- `DROP COLUMN`
- `DROP INDEX` (unless replacing)
- `ALTER TABLE ... DROP CONSTRAINT`

**DOWN migrations:**
- Optional, primarily for development rollback
- Never run in production
- If a migration needs to be "undone" in production, create a new forward migration

**Rationale:** Destructive changes risk data loss and cannot be safely reversed. Deploy forward-only fixes instead.

## Testing

### Unit Tests
```bash
make test-unit
```

### E2E Tests
```bash
make e2e
```

## Git

### Commit Signing
Commits should be made **without GPG signing** (use `--no-gpg-sign` or `-c commit.gpgsign=false`):
```bash
git commit --no-gpg-sign -m "message"
# or
git -c commit.gpgsign=false commit -m "message"
```

### Pre-commit Hooks
Setup pre-commit hooks to run all tests before committing:
```bash
make setup-hooks
```

This installs a pre-commit hook that runs:
- `make test` (Go unit tests + frontend tests)
- `make e2e` (E2E tests)

## Code Style

- Follow Go idioms and standard formatting (`gofmt`)
- Explicit error handling (no panic in library code)
- Table-driven tests preferred
