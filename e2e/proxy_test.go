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

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// mockPrivadoVerifier is a mock for E2E testing
type mockPrivadoVerifier struct {
	userDID string
}

func (m *mockPrivadoVerifier) CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error) {
	return &protocol.AuthorizationRequestMessage{
		ID:       "mock-request-id",
		ThreadID: "mock-thread-id",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/request",
		From:     verifierID,
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
		},
	}, nil
}

func (m *mockPrivadoVerifier) CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string, hc auth.HumanityRequestConfig) (*protocol.AuthorizationRequestMessage, error) {
	circuitID := hc.CircuitID
	if circuitID == "" {
		circuitID = "credentialAtomicQueryMTPV2"
	}
	credentialSubject, _ := hc.Query["credentialSubject"]
	if credentialSubject == nil {
		credentialSubject = map[string]any{"isHuman": map[string]any{"$eq": 1}}
	}
	credType := hc.CredentialType
	if credType == "" {
		credType = "ProofOfHumanity"
	}
	return &protocol.AuthorizationRequestMessage{
		ID:       "mock-request-id",
		ThreadID: "mock-thread-id",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/request",
		From:     verifierID,
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
			Scope: []protocol.ZeroKnowledgeProofRequest{
				{
					ID:        1,
					CircuitID: circuitID,
					Query: map[string]any{
						"allowedIssuers":    []string{issuerDID},
						"credentialSubject": credentialSubject,
						"context":           hc.SchemaURL,
						"type":              credType,
					},
				},
			},
		},
	}, nil
}

func (m *mockPrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
	// Return the user DID based on the JWZ token
	// For E2E tests, we'll use the token as a simple identifier
	if m.userDID != "" {
		return m.userDID, nil
	}
	// Default: extract DID from token or use a default
	return "did:privado:test_user", nil
}

func (m *mockPrivadoVerifier) VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error) {
	did, err := m.VerifyJWZ(ctx, jwzToken, authRequest, verifierID)
	if err != nil {
		return nil, err
	}
	return &auth.VerificationResult{UserDID: did}, nil
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

	// Connect to database and reset it for clean test state
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("Failed to reset test database: %v", err)
	}
	database.Close()

	// Find an available port first
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	serverAddr := fmt.Sprintf(":%d", port)
	serverURL := fmt.Sprintf("http://localhost:%d", port)

	cfg := &config.Config{
		NodeURL:     "http://localhost:8545",
		DatabaseURL: dbURL,
		// RD-1147: audit logs live in a separate DB via the real server.New path.
		// For e2e, co-locate the audit schema in this same testcontainer DB (the
		// lean audit migration is idempotent — CREATE ... IF NOT EXISTS — so it just
		// recreates access_logs here after main dropped it). Production keeps the
		// audit DB strictly separate; owner creds here are fine (the INSERT-only
		// seal is exercised by the internal/db integration test, not e2e).
		AuditDatabaseURL:      dbURL,
		AuditAdminDatabaseURL: dbURL,
		PrivadoRPCURL:         "https://rpc-mainnet.privado.id",
		IPFSGateway:           "https://ipfs-proxy-cache.privado.id",
		JWTSecret:             "test-secret",
		JWTRefreshSecret:      "test-refresh-secret",
		VerifierID:            "did:privado:verifier:test",
		BaseURL:               serverURL,
		Environment:           "development",
		// AllowMockLogin is inert without the mockauth build tag
		// (auth_prod.go stubs tryMockLogin out); enabling it here is
		// safe for production builds and lets mockauth-tagged tests
		// mint per-DID JWTs via the mock.<did> token format.
		AllowMockLogin: true,
	}

	// Use mock verifier if provided, otherwise create real one
	srv, err := server.NewWithVerifier(cfg, verifier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Reset database for fresh test (clears data, preserves schema)
	if err := db.ResetTestDatabase(srv.DB()); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

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

// getJWTToken performs the auth flow and returns a JWT access token
func getJWTToken(t *testing.T, serverURL, userDID string) string {
	client := &http.Client{Timeout: 5 * time.Second}

	// Step 1: Request authorization
	req, _ := http.NewRequest("POST", serverURL+"/auth/request", nil)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auth request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("auth request returned %d: %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(resp.Body).Decode(&authResp)

	// Step 2: Verify with mock token (dev mode)
	verifyBody := map[string]any{
		"session_id": authResp.SessionID,
		"jwz_token":  "mock." + userDID, // Mock token format
	}
	jsonBody, _ := json.Marshal(verifyBody)

	req2, _ := http.NewRequest("POST", serverURL+"/auth/verify", bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("auth verify failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("auth verify returned %d: %s", resp2.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp2.Body).Decode(&tokenResp)

	return tokenResp.AccessToken
}

// createRBACUser creates a user in the RBAC system with the specified properties
func createRBACUser(t *testing.T, database *db.DB, externalID string, kyc, banned bool) {
	ctx := context.Background()
	// database implements rbac.Store interface

	// Ensure default organization exists
	org := &rbac.Organization{
		ID:       rbac.DefaultOrgID,
		Slug:     "default",
		Name:     "Default Organization",
		Settings: map[string]any{},
	}
	_ = database.CreateOrganization(ctx, org) // Ignore error if already exists

	// Ensure default group exists
	group := &rbac.Group{
		ID:    rbac.DefaultGroupID,
		OrgID: rbac.DefaultOrgID,
		Slug:  "default",
		Name:  "Default Group",
		Depth: 0,
		Path:  "default",
	}
	_ = database.CreateGroup(ctx, group) // Ignore error if already exists

	// Ensure default group has access permissions
	groupAccess := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        rbac.DefaultGroupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId", "eth_estimateGas", "eth_gasPrice", "eth_getCode", "eth_getLogs", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_sendRawTransaction", "net_version"},
		Claims:         []rbac.Claim{},
	}
	_ = database.CreateGroupAccess(ctx, groupAccess) // Ignore error if already exists

	// Create user
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: externalID,
		KYC:        kyc,
		Banned:     banned,
		Metadata:   make(map[string]any),
	}

	if err := database.CreateUser(ctx, user); err != nil {
		t.Fatalf("failed to create RBAC user: %v", err)
	}

	// Add to default group (permissions come from GroupAccess, not roles)
	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: rbac.DefaultGroupID,
		Source:  rbac.MembershipSourceAdmin,
	}

	if err := database.CreateMembership(ctx, membership); err != nil {
		t.Fatalf("failed to create RBAC membership: %v", err)
	}
}

func TestE2E_Proxy_JSONRPCWithAuth(t *testing.T) {
	userDID := "did:privado:test_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=true (required for access)
	createRBACUser(t, srv.DB(), userDID, true, false)

	// Get JWT token using the auth flow
	accessToken := getJWTToken(t, serverURL, userDID)

	// Make JSON-RPC request with JWT token
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
		"id":      1,
	}

	jsonBody, _ := json.Marshal(reqBody)

	// Use /rpc/:org_id — explicit org required since getUserDefaultOrganization was removed (RD-877)
	req, _ := http.NewRequest("POST", serverURL+"/rpc/"+rbac.DefaultOrgID, bytes.NewReader(jsonBody))
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

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "unauthorized", "token")
}

func TestE2E_ForbiddenRequest_DisallowedMethod(t *testing.T) {
	userDID := "did:privado:restricted_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=true
	createRBACUser(t, srv.DB(), userDID, true, false)

	// Get JWT token
	accessToken := getJWTToken(t, serverURL, userDID)

	// Try to call a blocked debug method (debug_storageRangeAt is blocked by prefix,
	// unlike debug_traceTransaction which is exempted via prefixBlockExemptions)
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "debug_storageRangeAt",
		"params":  []any{"0x123"},
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "debug", "disallowed")
}

func TestE2E_BannedUser(t *testing.T) {
	userDID := "did:privado:banned_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=true, NOT banned yet (so /auth/verify succeeds)
	createRBACUser(t, srv.DB(), userDID, true, false)

	// Get JWT token while user is still active
	accessToken := getJWTToken(t, serverURL, userDID)

	// Now ban the user via direct DB update
	_, err := srv.DB().Conn().ExecContext(context.Background(),
		"UPDATE users SET banned = true, updated_at = CURRENT_TIMESTAMP WHERE external_id = $1",
		userDID)
	if err != nil {
		t.Fatalf("failed to ban user: %v", err)
	}

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "banned")
}

func TestE2E_NoKYC(t *testing.T) {
	userDID := "did:privado:no_kyc_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=false
	createRBACUser(t, srv.DB(), userDID, false, false)

	// Get JWT token (even non-KYC users can get tokens, but requests will be blocked)
	accessToken := getJWTToken(t, serverURL, userDID)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "kyc")
}
