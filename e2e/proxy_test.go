package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/server"
	
	_ "github.com/jackc/pgx/v5/stdlib"
)

// mockPrivadoVerifier is a mock for E2E testing
type mockPrivadoVerifier struct {
	userDID string
}

func (m *mockPrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string) (string, error) {
	// Return the user DID based on the JWZ token
	// For E2E tests, we'll use the token as a simple identifier
	if m.userDID != "" {
		return m.userDID, nil
	}
	// Default: extract DID from token or use a default
	return "did:privado:test_user", nil
}

func setupE2E(t *testing.T) (*server.Server, string, func()) {
	return setupE2EWithVerifier(t, nil)
}

func setupE2EWithVerifier(t *testing.T, verifier server.PrivadoVerifier) (*server.Server, string, func()) {
	// Use test database URL from environment or testcontainers
	dbURL := os.Getenv("TEST_DATABASE_URL")
	var cleanupDB func()
	
	if dbURL == "" {
		// Use testcontainers for automatic PostgreSQL setup
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		cleanupDB = cleanup
		t.Cleanup(cleanupDB)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
		cleanupDB = func() {}
	}
	
	cfg := &config.Config{
		NodeURL:          "http://localhost:8545",
		DatabaseURL:      dbURL,
		BillionsURL:      "http://localhost:9000", // Not used anymore, but kept for compatibility
		PrivadoRPCURL:    "https://rpc-mainnet.privado.id",
		IPFSGateway:      "https://ipfs-proxy-cache.privado.id",
		JWTSecret:        "test-secret",
		JWTRefreshSecret: "test-refresh-secret",
	}
	
	// Use mock verifier if provided, otherwise create real one
	srv := server.NewWithVerifier(cfg, verifier)
	
	// Find an available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	
	serverAddr := fmt.Sprintf(":%d", port)
	serverURL := fmt.Sprintf("http://localhost:%d", port)
	
	// Start server in goroutine
	go func() {
		if err := srv.Run(serverAddr); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()
	
	// Wait for server to start and be ready
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(serverURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if i == maxRetries-1 {
			t.Fatalf("server failed to start on %s", serverURL)
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	cleanup := func() {
		// Database cleanup handled by test isolation
		if cleanupDB != nil {
			cleanupDB()
		}
	}
	
	return srv, serverURL, cleanup
}

// getJWTToken calls /auth endpoint on the running server and returns the access token
func getJWTToken(t *testing.T, serverURL, userDID string) string {
	// Call /auth endpoint with mock JWZ token
	authReq := map[string]interface{}{
		"jwz_token": "mock.jwz.token." + userDID,
	}
	authBody, _ := json.Marshal(authReq)
	
	req, _ := http.NewRequest("POST", serverURL+"/auth", bytes.NewReader(authBody))
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auth request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var authResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		t.Fatalf("failed to decode auth response: %v", err)
	}
	
	accessToken, ok := authResp["access_token"].(string)
	if !ok {
		t.Fatalf("access_token not found in response: %v", authResp)
	}
	
	return accessToken
}

func TestE2E_AuthorizedRequest(t *testing.T) {
	userDID := "did:privado:test_user"
	
	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()
	
	// Get database and create policy
	database := srv.DB()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   userDID,
		KYC:          true,
		AllowMethods: []string{"eth_call", "eth_getBalance"},
		Banned:       false,
	}
	database.SetPolicy(policy)
	
	// Get JWT token by calling /auth
	accessToken := getJWTToken(t, serverURL, userDID)
	
	// Make JSON-RPC request with JWT token
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
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
	userDID := "did:privado:test_user"
	
	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()
	
	// Get database and create policy with restricted methods
	database := srv.DB()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   userDID,
		KYC:          true,
		AllowMethods: []string{"eth_call"}, // Only eth_call allowed
		Banned:       false,
	}
	database.SetPolicy(policy)
	
	// Get JWT token by calling /auth
	accessToken := getJWTToken(t, serverURL, userDID)
	
	// Try to call disallowed method
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendTransaction",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
	userDID := "did:privado:banned_user"
	
	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()
	
	// Get database and create banned policy
	database := srv.DB()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   userDID,
		KYC:          true,
		AllowMethods: []string{"eth_call"},
		Banned:       true,
	}
	database.SetPolicy(policy)
	
	// Get JWT token by calling /auth (even banned users can get tokens, but requests will be blocked)
	accessToken := getJWTToken(t, serverURL, userDID)
	
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
	userDID := "did:privado:no_kyc_user"
	
	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()
	
	// Get database and create policy without KYC
	database := srv.DB()
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
	database.Migrate()
	
	policy := &db.AccessPolicy{
		ExternalID:   userDID,
		KYC:          false,
		AllowMethods: []string{"eth_call"},
		Banned:       false,
	}
	database.SetPolicy(policy)
	
	// Get JWT token by calling /auth (even non-KYC users can get tokens, but requests will be blocked)
	accessToken := getJWTToken(t, serverURL, userDID)
	
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []interface{}{},
		"id":      1,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
