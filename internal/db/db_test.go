package db

import (
	"context"
	"os"
	"testing"
)

func setupTestDB(t *testing.T) *DB {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")
	
	if dbURL == "" {
		// Use testcontainers for local development (no external PostgreSQL needed)
		var cleanup func()
		dbURL, cleanup = SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
	}
	
	database, err := New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	
	// Clean up tables for fresh test
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS schema_version")
	database.Migrate(context.Background())
	
	return database
}

func cleanupTestDB(t *testing.T, database *DB) {
	database.Close()
}

func TestSetAndGetPolicy(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	policy := &AccessPolicy{
		ExternalID:   "billions:user_123",
		KYC:          true,
		AllowMethods: []string{"eth_call", "eth_getBalance"},
		Banned:       false,
		Note:         "test user",
	}
	
	// Set policy
	if err := database.SetPolicy(policy); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}
	
	// Get policy
	got, err := database.GetPolicy("billions:user_123")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	
	if got == nil {
		t.Fatal("got nil policy")
	}
	
	if got.ExternalID != policy.ExternalID {
		t.Errorf("got ExternalID %q, want %q", got.ExternalID, policy.ExternalID)
	}
	
	if got.KYC != policy.KYC {
		t.Errorf("got KYC %v, want %v", got.KYC, policy.KYC)
	}
	
	if len(got.AllowMethods) != len(policy.AllowMethods) {
		t.Errorf("got %d methods, want %d", len(got.AllowMethods), len(policy.AllowMethods))
	}
	
	if got.Banned != policy.Banned {
		t.Errorf("got Banned %v, want %v", got.Banned, policy.Banned)
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	policy, err := database.GetPolicy("billions:nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if policy != nil {
		t.Errorf("expected nil policy, got %v", policy)
	}
}

func TestListPolicies(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	policies := []*AccessPolicy{
		{
			ExternalID:   "billions:user_1",
			KYC:          true,
			AllowMethods: []string{"eth_call"},
		},
		{
			ExternalID:   "billions:user_2",
			KYC:          false,
			AllowMethods: []string{"eth_getBalance"},
		},
	}
	
	for _, p := range policies {
		if err := database.SetPolicy(p); err != nil {
			t.Fatalf("failed to set policy: %v", err)
		}
	}
	
	list, err := database.ListPolicies()
	if err != nil {
		t.Fatalf("failed to list policies: %v", err)
	}
	
	if len(list) != len(policies) {
		t.Errorf("got %d policies, want %d", len(list), len(policies))
	}
}

func TestLogAccess(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	// Create a policy first (required for foreign key constraint)
	policy := &AccessPolicy{
		ExternalID:   "billions:user_123",
		KYC:          true,
		AllowMethods: []string{"eth_call"},
		Banned:       false,
	}
	if err := database.SetPolicy(policy); err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	
	// Now log access
	if err := database.LogAccess("billions:user_123", "eth_call", 200, "127.0.0.1"); err != nil {
		t.Fatalf("failed to log access: %v", err)
	}
	
	logs, err := database.GetAccessLogs(10)
	if err != nil {
		t.Fatalf("failed to get logs: %v", err)
	}
	
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	
	if logs[0].ExternalID != "billions:user_123" {
		t.Errorf("got ExternalID %q, want billions:user_123", logs[0].ExternalID)
	}
	
	if logs[0].Method != "eth_call" {
		t.Errorf("got Method %q, want eth_call", logs[0].Method)
	}
	
	if logs[0].StatusCode != 200 {
		t.Errorf("got StatusCode %d, want 200", logs[0].StatusCode)
	}
}
