package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/server"
	
	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupE2E(t *testing.T) (*server.Server, func()) {
	// Use test database URL from environment or default
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_e2e_test?sslmode=disable"
	}
	
	// Ensure test database exists
	if err := db.EnsureTestDatabase(dbURL); err != nil {
		t.Logf("Warning: Could not ensure test database exists: %v", err)
		t.Logf("Please create the database manually: createdb privacy_proxy_e2e_test")
		// Continue anyway - might already exist
	}
	
	cfg := &config.Config{
		NodeURL:     "http://localhost:8545",
		DatabaseURL: dbURL,
		BillionsURL: "http://localhost:9000",
	}
	
	srv := server.New(cfg)
	
	// Start server in goroutine
	go func() {
		if err := srv.Run(":8081"); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()
	
	// Wait for server to start
	time.Sleep(100 * time.Millisecond)
	
	cleanup := func() {
		// Database cleanup handled by test isolation
	}
	
	return srv, cleanup
}

func TestE2E_AuthorizedRequest(t *testing.T) {
	_, cleanup := setupE2E(t)
	defer cleanup()
	
	// Create a policy for the test user
	cfg := &config.Config{
		DatabaseURL: os.Getenv("TEST_DATABASE_URL"),
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_e2e_test?sslmode=disable"
	}
	database, _ := db.New(cfg.DatabaseURL)
	defer database.Close()
	// Clean and migrate
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   "billions:test_user",
		KYC:          true,
		AllowMethods: []string{"eth_call", "eth_getBalance"},
		Banned:       false,
	}
	database.SetPolicy(policy)
	
	// Make request
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", "http://localhost:8081/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer test_user")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 or 502 (node might not be running), got %d: %s", resp.StatusCode, string(body))
	}
}

func TestE2E_UnauthorizedRequest_NoToken(t *testing.T) {
	_, cleanup := setupE2E(t)
	defer cleanup()
	
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", "http://localhost:8081/", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestE2E_ForbiddenRequest_DisallowedMethod(t *testing.T) {
	_, cleanup := setupE2E(t)
	defer cleanup()
	
	// Create a policy that doesn't allow eth_sendTransaction
	cfg := &config.Config{
		DatabaseURL: os.Getenv("TEST_DATABASE_URL"),
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_e2e_test?sslmode=disable"
	}
	database, _ := db.New(cfg.DatabaseURL)
	defer database.Close()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   "billions:test_user",
		KYC:          true,
		AllowMethods: []string{"eth_call"}, // Only eth_call allowed
		Banned:       false,
	}
	database.SetPolicy(policy)
	
	// Try to call disallowed method
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendTransaction",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", "http://localhost:8081/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer test_user")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestE2E_BannedUser(t *testing.T) {
	_, cleanup := setupE2E(t)
	defer cleanup()
	
	// Create a banned policy
	cfg := &config.Config{
		DatabaseURL: os.Getenv("TEST_DATABASE_URL"),
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_e2e_test?sslmode=disable"
	}
	database, _ := db.New(cfg.DatabaseURL)
	defer database.Close()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   "billions:banned_user",
		KYC:          true,
		AllowMethods: []string{"eth_call"},
		Banned:       true,
	}
	database.SetPolicy(policy)
	
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", "http://localhost:8081/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer banned_user")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestE2E_NoKYC(t *testing.T) {
	_, cleanup := setupE2E(t)
	defer cleanup()
	
	// Create a policy without KYC
	cfg := &config.Config{
		DatabaseURL: os.Getenv("TEST_DATABASE_URL"),
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_e2e_test?sslmode=disable"
	}
	database, _ := db.New(cfg.DatabaseURL)
	defer database.Close()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   "billions:no_kyc_user",
		KYC:          false,
		AllowMethods: []string{"eth_call"},
		Banned:       false,
	}
	database.SetPolicy(policy)
	
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", "http://localhost:8081/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer no_kyc_user")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403 (KYC required), got %d: %s", resp.StatusCode, string(body))
	}
}
