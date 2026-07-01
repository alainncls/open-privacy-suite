// Package migrationsaudit provides embedded SQL migrations that run ONLY
// against the separate append-only audit database (RD-1147).
//
// These are applied AFTER the shared schema migrations (internal/db/migrations)
// have run against the audit-admin pool, so the access_logs table + the
// privacy_proxy_app / privacy_proxy_admin roles from migration 058 already
// exist. This FS then tightens access_logs to INSERT-only for the runtime role.
//
// It is intentionally SEPARATE from the shared FS: it must never run against the
// main DATABASE_URL (that would make the main-DB retention worker, which runs as
// privacy_proxy_app and needs UPDATE/DELETE on access_logs, fail loudly).
package migrationsaudit

import "embed"

// FS contains the audit-database-only SQL migrations.
//
//go:embed *.sql
var FS embed.FS
