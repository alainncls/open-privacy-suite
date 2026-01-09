package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
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
