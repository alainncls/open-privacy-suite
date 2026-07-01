package db_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
)

// TestAccessLogsSeparateAuditDB is the RD-1147 acceptance test: it provisions a
// SEPARATE audit Postgres with a restricted runtime role (privacy_proxy_app,
// sealed to INSERT-only by the audit-only migration) and an owner/admin role,
// then proves:
//   - the admin pool migrates the audit DB (shared schema + append-only REVOKE);
//   - the restricted runtime role is DENIED UPDATE/DELETE on access_logs (the seal);
//   - a chained access_logs write via the runtime role lands in the AUDIT DB and
//     NOT the main DB, and reads (with org-scoping) come back from the audit DB;
//   - the verifier verifies the audit-DB chain;
//   - prune via the ADMIN pool works (the runtime role could not).
//
// It requires Docker (testcontainers). The seal proof is the security-critical
// assertion: it is what makes access_logs actually append-only for the runtime
// identity.
func TestAccessLogsSeparateAuditDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping two-container integration test in -short mode")
	}
	ctx := context.Background()

	// --- main DB (owner role) -------------------------------------------------
	mainURL, mainCleanup := db.SetupTestContainer(t)
	t.Cleanup(mainCleanup)
	mainDB, err := db.New(mainURL)
	if err != nil {
		t.Fatalf("open main DB: %v", err)
	}
	t.Cleanup(func() { mainDB.Close() })

	// --- audit DB: admin pool runs shared + audit-only migrations -------------
	auditURL, auditCleanup := db.SetupTestContainer(t)
	t.Cleanup(auditCleanup)
	auditAdminDB, err := db.New(auditURL) // owner role: runs shared migration FS
	if err != nil {
		t.Fatalf("open audit admin DB: %v", err)
	}
	t.Cleanup(func() { auditAdminDB.Close() })
	if err := auditAdminDB.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
		t.Fatalf("apply audit-only migrations: %v", err)
	}

	// --- provision a restricted LOGIN role in the audit DB --------------------
	// privacy_proxy_app is created NOLOGIN by migration 058; grant it a password
	// + LOGIN here so we can connect AS the restricted role for the runtime DSN.
	const restrictedPassword = "app-restricted-pw"
	adminConn := auditAdminDB.Conn()
	if _, err := adminConn.ExecContext(ctx,
		fmt.Sprintf("ALTER ROLE privacy_proxy_app WITH LOGIN PASSWORD '%s'", restrictedPassword)); err != nil {
		t.Fatalf("grant LOGIN to privacy_proxy_app: %v", err)
	}
	// Build the runtime DSN by swapping the credential in auditURL. The 058
	// grants (+ the audit-only migration) fully define what this role may do.
	runtimeURL := rewriteDSNCredential(t, auditURL, "privacy_proxy_app", restrictedPassword)

	auditRuntimeDB, err := db.NewWithoutMigrate(runtimeURL) // restricted role, no DDL
	if err != nil {
		t.Fatalf("open audit runtime DB (restricted role): %v", err)
	}
	t.Cleanup(func() { auditRuntimeDB.Close() })

	// --- SEAL PROOF: restricted role DENIED UPDATE/DELETE on access_logs ------
	// Seed one row via the admin pool so there IS a row to (attempt to) mutate.
	seedChain := audit.NewHashChain("")
	if _, _, _, err := auditAdminDB.LogAccessChained(ctx, seedChain, "did:test:seed", "eth_chainId", 200, "127.0.0.1", "corr-seed", nil, nil, "org-seed", ""); err != nil {
		t.Fatalf("seed access_logs via admin: %v", err)
	}
	rc := auditRuntimeDB.Conn()
	if _, err := rc.ExecContext(ctx, `UPDATE access_logs SET status_code = 999`); err == nil {
		t.Fatal("SEAL BROKEN: restricted runtime role was allowed to UPDATE access_logs")
	} else if !isPermissionDenied(err) {
		t.Fatalf("expected permission-denied on UPDATE, got: %v", err)
	}
	if _, err := rc.ExecContext(ctx, `DELETE FROM access_logs`); err == nil {
		t.Fatal("SEAL BROKEN: restricted runtime role was allowed to DELETE from access_logs")
	} else if !isPermissionDenied(err) {
		t.Fatalf("expected permission-denied on DELETE, got: %v", err)
	}
	// And the runtime role CAN still INSERT (append-only) + SELECT.
	if _, err := rc.ExecContext(ctx, `SELECT count(*) FROM access_logs`); err != nil {
		t.Fatalf("restricted role should be able to SELECT access_logs: %v", err)
	}

	// --- write via runtime role lands in AUDIT DB, not MAIN -------------------
	runtimeChainSeed, err := auditRuntimeDB.GetLatestAccessLogHashForChain(ctx, "access_logs")
	if err != nil {
		t.Fatalf("seed runtime chain: %v", err)
	}
	runtimeChain := audit.NewHashChain(runtimeChainSeed)
	if _, _, _, err := auditRuntimeDB.LogAccessChained(ctx, runtimeChain, "did:test:alice", "eth_getLogs", 200, "10.0.0.1", "corr-alice", nil, nil, "org-A", ""); err != nil {
		t.Fatalf("chained write via runtime role: %v", err)
	}

	// The write must NOT appear in the main DB.
	mainCount, err := mainDB.CountAccessLogs(ctx, db.AccessLogFilter{})
	if err != nil {
		t.Fatalf("count main access_logs: %v", err)
	}
	if mainCount != 0 {
		t.Fatalf("access_logs write leaked into MAIN db: got %d rows, want 0", mainCount)
	}

	// It must appear in the audit DB, readable via the runtime role.
	auditLogs, err := auditRuntimeDB.GetAccessLogs(ctx, db.AccessLogFilter{ExternalID: "did:test:alice", Limit: 10})
	if err != nil {
		t.Fatalf("read audit access_logs: %v", err)
	}
	if len(auditLogs) != 1 || auditLogs[0].Method != "eth_getLogs" {
		t.Fatalf("expected 1 alice row in audit db, got %+v", auditLogs)
	}

	// --- org-scoping (org_id = ANY) still works on the audit DB ---------------
	scopedA, err := auditRuntimeDB.GetAccessLogs(ctx, db.AccessLogFilter{OrgIDs: []string{"org-A"}, Limit: 100})
	if err != nil {
		t.Fatalf("org-scoped read (org-A): %v", err)
	}
	if len(scopedA) != 1 {
		t.Fatalf("org-A scoped read: got %d rows, want 1", len(scopedA))
	}
	scopedOther, err := auditRuntimeDB.GetAccessLogs(ctx, db.AccessLogFilter{OrgIDs: []string{"org-does-not-exist"}, Limit: 100})
	if err != nil {
		t.Fatalf("org-scoped read (other): %v", err)
	}
	if len(scopedOther) != 0 {
		t.Fatalf("cross-org read leak: got %d rows for a foreign org, want 0", len(scopedOther))
	}

	// --- verifier verifies the audit-DB chain (read via admin conn) -----------
	verifier := audit.NewVerifier(auditAdminDB.Conn(), auditAdminDB)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain failed verification: %+v", res)
	}

	// --- prune via the ADMIN pool works (runtime role could not) --------------
	// Delete everything older than "now + 1h" so every seeded row is pruned.
	cutoff := time.Now().UTC().Add(time.Hour)
	pr, err := auditAdminDB.CleanupAccessLogs(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune via admin pool: %v", err)
	}
	if pr.Deleted == 0 {
		t.Fatalf("expected admin prune to delete rows, deleted 0")
	}
	remaining, err := auditAdminDB.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("count after prune: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 rows after prune, got %d", remaining)
	}
	// The anchor preserves the chain seed across the prune cut.
	if pr.AnchorHash == "" {
		t.Fatal("expected prune to record a chain anchor hash")
	}
}

// TestAccessLogs_BothURLsUnset_MainDBRegression is the non-breaking guard: when
// no separate audit DB is configured, the same *DB handle serves as main and
// audit, and access_logs writes/reads/prune all work against it unchanged. This
// mirrors the server wiring's auditDB == database fallback.
func TestAccessLogs_BothURLsUnset_MainDBRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container integration test in -short mode")
	}
	ctx := context.Background()

	dbURL, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	// auditDB == database (the unset fallback).
	auditDB := database

	seed, err := auditDB.GetLatestAccessLogHashForChain(ctx, "access_logs")
	if err != nil {
		t.Fatalf("seed chain: %v", err)
	}
	chain := audit.NewHashChain(seed)
	if _, _, _, err := auditDB.LogAccessChained(ctx, chain, "did:test:bob", "eth_call", 200, "127.0.0.1", "corr-bob", nil, nil, "org-B", ""); err != nil {
		t.Fatalf("chained write: %v", err)
	}

	// Read from the same (main) DB.
	logs, err := auditDB.GetAccessLogs(ctx, db.AccessLogFilter{ExternalID: "did:test:bob", Limit: 10})
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 row in main db, got %d", len(logs))
	}

	// The same handle can prune (owner role has full CRUD in the main DB).
	if _, err := auditDB.CleanupAccessLogs(ctx, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("prune on main db: %v", err)
	}
}

// rewriteDSNCredential returns dsn with its user/password replaced, preserving
// host/port/db. Used to derive a restricted-role DSN from the owner DSN.
func rewriteDSNCredential(t *testing.T, dsn, user, password string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		user, password, cfg.Host, cfg.Port, cfg.Database)
}

// isPermissionDenied reports whether err is a Postgres "permission denied" error
// (SQLSTATE 42501) — the expected outcome when the sealed runtime role attempts
// UPDATE/DELETE on access_logs.
func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "42501")
}
