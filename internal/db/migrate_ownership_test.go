package db_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
)

// The audit database's documented lifecycle is: start on the derived DSNs (which
// connect as DATABASE_URL's owner), then point AUDIT_ADMIN_DATABASE_URL at the
// dedicated privacy_proxy_admin role. That leaves schema_version_audit owned by
// the first role while the second one migrates it. tern >= 2.4 retro-fits a
// PRIMARY KEY onto a pre-existing version table, which is an ALTER TABLE and so
// needs ownership — so that (previously working) deployment starts failing with
// a bare "must be owner of table ... (SQLSTATE 42501)".
//
// These tests pin the diagnosis down to the exact combination tern fails on, and
// assert the error tells the operator what to run.

// asRole returns dsn rewritten to connect as the given role.
func asRole(t *testing.T, dsn, role, password string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	parsed.User = url.UserPassword(role, password)
	return parsed.String()
}

// dropVersionTablePrimaryKey reproduces a version table created by tern < 2.4.
func dropVersionTablePrimaryKey(t *testing.T, database *db.DB) {
	t.Helper()
	_, err := database.Conn().ExecContext(context.Background(),
		`ALTER TABLE schema_version_audit DROP CONSTRAINT IF EXISTS schema_version_audit_pkey`)
	if err != nil {
		t.Fatalf("drop version table primary key: %v", err)
	}
}

// grantMigratorRole creates a login role with full privileges on the audit
// schema but NO ownership — exactly what audit/001 grants privacy_proxy_admin.
func grantMigratorRole(t *testing.T, database *db.DB, role, password string) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + password + `'`,
		`GRANT USAGE, CREATE ON SCHEMA public TO ` + role,
		`GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ` + role,
		`GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ` + role,
	} {
		if _, err := database.Conn().ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func TestMigrateAuditOnly_NonOwnerWithoutPrimaryKey_ExplainsTheFix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}
	auditURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	owner := migrateAuditDB(t, auditURL)
	defer owner.Close()

	// Rewind to the pre-tern-2.4 shape, then migrate as a non-owner.
	dropVersionTablePrimaryKey(t, owner)
	grantMigratorRole(t, owner, "audit_migrator", "migratorpass")

	migrator, err := db.NewWithoutMigrate(asRole(t, auditURL, "audit_migrator", "migratorpass"))
	if err != nil {
		t.Fatalf("open audit DB as non-owner: %v", err)
	}
	defer migrator.Close()

	err = migrator.MigrateAuditOnly(context.Background(), migrationsaudit.FS)
	if err == nil {
		t.Fatal("expected the migration to fail for a non-owner, got nil")
	}

	got := err.Error()
	for _, want := range []string{
		"schema_version_audit",     // which table
		"audit_migrator",           // who is connected
		"OWNER TO",                 // the remediation
		"REASSIGN OWNED BY",        // the remediation for a whole audit schema
		"AUDIT_ADMIN_DATABASE_URL", // where this configuration comes from
	} {
		if !strings.Contains(got, want) {
			t.Errorf("error should mention %q, got: %v", want, got)
		}
	}
	// The point of the check is to replace the opaque driver error.
	if strings.Contains(got, "SQLSTATE") {
		t.Errorf("expected an actionable error rather than a raw SQLSTATE, got: %v", got)
	}
}

func TestMigrateAuditOnly_NonOwnerWithPrimaryKey_StillMigrates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}
	auditURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	owner := migrateAuditDB(t, auditURL)
	defer owner.Close()

	// Primary key already in place: tern never issues the ALTER TABLE, so a
	// non-owner must keep migrating exactly as it did before. This is what keeps
	// the check from breaking deployments that are fine today.
	grantMigratorRole(t, owner, "audit_migrator", "migratorpass")

	migrator, err := db.NewWithoutMigrate(asRole(t, auditURL, "audit_migrator", "migratorpass"))
	if err != nil {
		t.Fatalf("open audit DB as non-owner: %v", err)
	}
	defer migrator.Close()

	if err := migrator.MigrateAuditOnly(context.Background(), migrationsaudit.FS); err != nil {
		t.Fatalf("migration should succeed when the version table already has its primary key: %v", err)
	}
}

func TestMigrateAuditOnly_Owner_AddsThePrimaryKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}
	auditURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	owner := migrateAuditDB(t, auditURL)
	defer owner.Close()

	dropVersionTablePrimaryKey(t, owner)

	// The owner can run the ALTER, so tern's retro-fit succeeds and the check
	// must stay out of the way.
	if err := owner.MigrateAuditOnly(context.Background(), migrationsaudit.FS); err != nil {
		t.Fatalf("owner migration failed: %v", err)
	}

	var hasPrimaryKey bool
	if err := owner.Conn().QueryRowContext(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_constraint
		                 WHERE conrelid = 'schema_version_audit'::regclass AND contype = 'p')`,
	).Scan(&hasPrimaryKey); err != nil {
		t.Fatalf("check primary key: %v", err)
	}
	if !hasPrimaryKey {
		t.Error("tern should have added the version table's primary key when run as owner")
	}
}
