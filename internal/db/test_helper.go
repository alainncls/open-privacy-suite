package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// EnsureTestDatabase creates the test database if it doesn't exist
// This is exported so it can be used by other test packages
func EnsureTestDatabase(dbURL string) error {
	// Parse the database URL to extract components
	// Format: postgres://user:password@host:port/database?sslmode=disable

	// Extract database name from URL
	parts := strings.Split(dbURL, "/")
	if len(parts) < 4 {
		return fmt.Errorf("invalid database URL format")
	}

	dbNamePart := strings.Split(parts[3], "?")[0]
	if dbNamePart == "" {
		return fmt.Errorf("no database name in URL")
	}

	// Create connection URL to 'postgres' database (default)
	baseURL := strings.Replace(dbURL, "/"+dbNamePart, "/postgres", 1)
	if idx := strings.Index(baseURL, "?"); idx == -1 {
		baseURL += "?sslmode=disable"
	}

	// Connect to postgres database to create test database
	conn, err := sql.Open("pgx", baseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	// Check if database exists (using parameterized query for safety)
	var exists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)"
	err = conn.QueryRow(checkQuery, dbNamePart).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check database existence: %w", err)
	}

	// Create database if it doesn't exist
	if !exists {
		// Terminate any existing connections to the database
		terminateQuery := `
			SELECT pg_terminate_backend(pg_stat_activity.pid)
			FROM pg_stat_activity
			WHERE pg_stat_activity.datname = $1
			AND pid <> pg_backend_pid()`
		conn.Exec(terminateQuery, dbNamePart)

		// Note: CREATE DATABASE doesn't support parameters, but dbNamePart is controlled
		// and only used in test code, so it's safe
		createQuery := fmt.Sprintf("CREATE DATABASE %s", dbNamePart)
		_, err = conn.Exec(createQuery)
		if err != nil {
			return fmt.Errorf("failed to create database: %w", err)
		}
	}

	return nil
}

// ResetTestDatabase clears all data tables to get a clean slate.
// This preserves the schema and migration state while clearing test data.
// This is useful when using an external PostgreSQL database that may have leftover data.
func ResetTestDatabase(database *DB) error {
	ctx := context.Background()
	conn := database.Conn()

	// Delete data from tables in correct order to respect foreign keys
	// This is safer than TRUNCATE which can cause deadlocks in concurrent tests
	tables := []string{
		"tx_visible_to",
		"rbac_audit_log",
		"effective_permissions_cache",
		"contract_grants",
		"contracts",
		"user_memberships",
		"group_access",
		"allowed_azure_tenants",
		"groups",
		"users",
		"organizations",
		"disclosure_access_events",
		"disclosure_reports",
		"disclosure_grants",
		"disclosure_requests",
		"refresh_tokens",
		"revoked_tokens",
		"access_logs",
		"audit_chain_anchor",
		// RD-1112 signed-checkpoint + break-glass tables. Stand-alone (no FK
		// cascade from access_logs), so they must be reset explicitly. Without
		// this, a checkpoint left by an earlier test/package on a SHARED Postgres
		// (CI) survives, and the verifier — which validates every chain_name's
		// checkpoint with the caller's single signer — rejects the foreign-key
		// signature (checkpoint_signature_invalid), an order-dependent flake.
		"audit_chain_checkpoint",
		"audit_chain_reanchor",
		"eth_address_links",
		// RD-993: stand-alone audit table (no FK cascade), so explicit reset
		// is required to keep tests isolated when they run against a shared
		// external Postgres (CI). Local testcontainer runs would otherwise
		// hide the leak.
		"oauth_silent_sso_log",
	}

	for _, table := range tables {
		_, err := conn.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			// Ignore errors for tables that might not exist
			if !strings.Contains(err.Error(), "does not exist") {
				return fmt.Errorf("failed to clear table %s: %w", table, err)
			}
		}
	}

	return nil
}

// SetupTestContainer starts a PostgreSQL testcontainer and returns the connection string
// This is the recommended approach for tests - no need for external PostgreSQL
// The container is automatically cleaned up when the test finishes
// If Docker is not available or testcontainers fails, falls back to external PostgreSQL
func SetupTestContainer(t *testing.T) (string, func()) {
	ctx := context.Background()

	// Try to start PostgreSQL container
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		// If testcontainers fails (Docker not available, network issues, etc.),
		// fall back to external PostgreSQL
		testcontainersErr := err
		t.Logf("Warning: testcontainers failed (%v), falling back to external PostgreSQL", testcontainersErr)
		t.Logf("Make sure PostgreSQL is running: docker-compose up -d postgres")

		// Use external PostgreSQL as fallback
		dbURL := "postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
		if err := EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("Both testcontainers and external PostgreSQL failed. Start PostgreSQL with: docker-compose up -d postgres\nTestcontainers error: %v\nExternal PostgreSQL error: %v", testcontainersErr, err)
		}

		// Return external DB URL with no-op cleanup
		return dbURL, func() {}
	}

	// Get connection string
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		// If we can't get connection string, try to terminate and fall back
		connStrErr := err
		postgresContainer.Terminate(ctx)
		t.Logf("Warning: failed to get connection string (%v), falling back to external PostgreSQL", connStrErr)

		dbURL := "postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
		if err := EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("Both testcontainers and external PostgreSQL failed. Start PostgreSQL with: docker-compose up -d postgres\nConnection string error: %v\nExternal PostgreSQL error: %v", connStrErr, err)
		}

		return dbURL, func() {}
	}

	// Cleanup function
	cleanup := func() {
		if err := postgresContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return connStr, cleanup
}
