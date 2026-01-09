package access

import (
	"os"
	"testing"

	"privacy-proxy/internal/db"
)

func setupTestDB(t *testing.T) *db.DB {
	// Use test database URL from environment or default
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
	}
	
	// Ensure test database exists
	if err := db.EnsureTestDatabase(dbURL); err != nil {
		t.Logf("Warning: Could not ensure test database exists: %v", err)
		t.Logf("Please create the database manually: createdb privacy_proxy_test")
		// Continue anyway - might already exist
	}
	
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	
	// Clean up tables for fresh test
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Migrate()
	
	return database
}

func cleanupTestDB(t *testing.T, database *db.DB) {
	database.Close()
}

func TestCheckAccess(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	ctrl := NewController(database)
	
	// Create a test policy
	policy := &db.AccessPolicy{
		ExternalID:   "billions:user_123",
		KYC:          true,
		AllowMethods: []string{"eth_call", "eth_getBalance"},
		Banned:       false,
	}
	
	if err := database.SetPolicy(policy); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}
	
	tests := []struct {
		name      string
		externalID string
		method    string
		wantErr   bool
	}{
		{
			name:       "allowed method",
			externalID: "billions:user_123",
			method:     "eth_call",
			wantErr:    false,
		},
		{
			name:       "another allowed method",
			externalID: "billions:user_123",
			method:     "eth_getBalance",
			wantErr:    false,
		},
		{
			name:       "disallowed method",
			externalID: "billions:user_123",
			method:     "eth_sendTransaction",
			wantErr:    true,
		},
		{
			name:       "non-existent user",
			externalID: "billions:unknown",
			method:     "eth_call",
			wantErr:    true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ctrl.CheckAccess(tt.externalID, tt.method)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCheckAccess_Banned(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	ctrl := NewController(database)
	
	// Create a banned policy
	policy := &db.AccessPolicy{
		ExternalID:   "billions:banned_user",
		KYC:          true,
		AllowMethods: []string{"eth_call"},
		Banned:       true,
	}
	
	if err := database.SetPolicy(policy); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}
	
	err := ctrl.CheckAccess("billions:banned_user", "eth_call")
	if err == nil {
		t.Errorf("expected error for banned user but got none")
	}
}

func TestCheckAccess_KYCRequired(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)
	
	ctrl := NewController(database)
	
	// Create a policy without KYC
	policy := &db.AccessPolicy{
		ExternalID:   "billions:no_kyc_user",
		KYC:          false,
		AllowMethods: []string{"eth_call"},
		Banned:       false,
	}
	
	if err := database.SetPolicy(policy); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}
	
	err := ctrl.CheckAccess("billions:no_kyc_user", "eth_call")
	if err == nil {
		t.Errorf("expected error for non-KYC user but got none")
	}
	
	if err != nil && err.Error() != "KYC required for billions:no_kyc_user" {
		t.Errorf("expected KYC error, got: %v", err)
	}
}
