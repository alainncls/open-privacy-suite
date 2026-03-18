package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test addresses and DIDs
const (
	testViewerWallet   = "0x1111111111111111111111111111111111111111"
	testViewerAddress2 = "0x1111111111111111111111111111111111111112"
	testTargetAddress  = "0x2222222222222222222222222222222222222222"
	testPublicAddress  = "0x3333333333333333333333333333333333333333"
	testUnknownWallet  = "0x4444444444444444444444444444444444444444"
	testViewerDID      = "did:privado:viewer_test"
	testTargetDID      = "did:privado:target_test"
)

// setupTestServerForExplorer creates a test server configured for explorer API tests
func setupTestServerForExplorer(t *testing.T) (*Server, *db.DB) {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		VerifierID:  "did:privado:verifier:test",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	disclosureService := disclosure.NewService(database)

	srv := &Server{
		db:                database,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbac.NewAccessController(database, 5*time.Minute),
		disclosureService: disclosureService,
		config:            cfg,
	}

	t.Cleanup(func() {
		srv.db.Close()
	})

	return srv, database
}

// setupExplorerRouter creates a router with explorer routes for testing.
// Includes OptionalJWTAuthMiddleware so tests can authenticate via Bearer token.
// Note: We skip the localhost middleware for unit tests.
func setupExplorerRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	explorer := router.Group("/api/v1/explorer")
	explorer.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorer.GET("/viewable-addresses", srv.getViewableAddresses)
	explorer.GET("/check-address/:address", srv.checkAddressVisibility)
	explorer.POST("/check-addresses", srv.batchCheckAddresses)

	return router
}

// issueTestJWT creates a valid JWT for the given DID using the test server's JWT service.
func issueTestJWT(t *testing.T, srv *Server, did string) string {
	t.Helper()
	token, err := srv.jwtService.IssueAccessToken(did, false)
	require.NoError(t, err)
	return token
}

// addBearerToken adds an Authorization: Bearer header with a valid JWT for the given DID.
func addBearerToken(t *testing.T, req *http.Request, srv *Server, did string) {
	t.Helper()
	req.Header.Set("Authorization", "Bearer "+issueTestJWT(t, srv, did))
}

// createTestUserForExplorer creates a test user and returns the user ID
func createTestUserForExplorer(t *testing.T, database *db.DB, externalID string) string {
	ctx := context.Background()
	userID := uuid.New().String()

	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, externalID)
	require.NoError(t, err)

	return userID
}

// linkEthAddressToUser links an ETH address to a user's DID
func linkEthAddressToUser(t *testing.T, database *db.DB, did, address string) {
	err := database.LinkEthAddress(context.Background(), did, address, "test-sig", "test-hash")
	require.NoError(t, err)
}

// createDisclosureGrant creates a disclosure grant between two users
// Returns the grant ID
func createDisclosureGrant(t *testing.T, database *db.DB, requesterDID, targetUserID string, expiresAt time.Time) string {
	ctx := context.Background()

	// Create default org if not exists
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// Create disclosure request
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, '{}', 'Test grant', 'approved', NOW())`,
		requestID, requesterDID, targetUserID, defaultOrgID)
	require.NoError(t, err)

	// Create grant
	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, '{}', NOW(), $4)`,
		grantID, requestID, "test-hash-"+grantID, expiresAt)
	require.NoError(t, err)

	return grantID
}

// ============================================================================
// Test: GET /api/v1/explorer/viewable-addresses
// ============================================================================

func TestExplorerAPI_GetViewableAddresses_MissingWalletAndDID(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "either wallet or JWT authentication is required")
}

func TestExplorerAPI_GetViewableAddresses_UnknownWallet(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testUnknownWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, testUnknownWallet, resp.ViewerWallet)
	assert.Empty(t, resp.ViewerDID)
	assert.Empty(t, resp.OwnAddresses)
	assert.Empty(t, resp.DisclosedAddresses)
}

func TestExplorerAPI_GetViewableAddresses_ReturnsOwnAddresses(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link addresses
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)
	linkEthAddressToUser(t, database, testViewerDID, testViewerAddress2)

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, testViewerWallet, resp.ViewerWallet)
	assert.Equal(t, testViewerDID, resp.ViewerDID)
	assert.Len(t, resp.OwnAddresses, 2)

	// Check that both addresses are returned
	addresses := make(map[string]bool)
	for _, a := range resp.OwnAddresses {
		addresses[a.Address] = true
	}
	assert.True(t, addresses[testViewerWallet])
	assert.True(t, addresses[testViewerAddress2])
}

func TestExplorerAPI_GetViewableAddresses_ReturnsDisclosedAddresses(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create disclosure grant from viewer to target
	createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, testViewerDID, resp.ViewerDID)
	assert.Len(t, resp.OwnAddresses, 1)
	assert.Len(t, resp.DisclosedAddresses, 1)
	assert.Equal(t, testTargetAddress, resp.DisclosedAddresses[0].Address)
	assert.Equal(t, testTargetDID, resp.DisclosedAddresses[0].OwnerDID)
}

func TestExplorerAPI_GetViewableAddresses_CaseInsensitive(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link address (lowercase)
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Query with uppercase wallet
	upperWallet := "0x1111111111111111111111111111111111111111"
	mixedWallet := "0x1111111111111111111111111111111111111111"

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+upperWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, mixedWallet, resp.ViewerWallet) // Normalized to lowercase
	assert.Len(t, resp.OwnAddresses, 1)
}

// ============================================================================
// Test: GET /api/v1/explorer/check-address/:address
// ============================================================================

func TestExplorerAPI_CheckAddressVisibility_MissingWalletAndDID(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "either wallet or JWT authentication is required")
}

func TestExplorerAPI_CheckAddressVisibility_OwnAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link address
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Check visibility of own address
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testViewerWallet+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Reason)
	assert.Equal(t, VisibilityFull, resp.Level)
}

func TestExplorerAPI_CheckAddressVisibility_PublicAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Check visibility of unlinked (public) address
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testPublicAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonPublicAddress, resp.Reason)
	assert.Equal(t, VisibilityFull, resp.Level)
}

func TestExplorerAPI_CheckAddressVisibility_DisclosedAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create disclosure grant
	grantID := createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonDisclosureGrant, resp.Reason)
	assert.Equal(t, VisibilityFull, resp.Level)
	assert.NotNil(t, resp.GrantID)
	assert.Equal(t, grantID, *resp.GrantID)
	assert.NotNil(t, resp.ExpiresAt)
}

func TestExplorerAPI_CheckAddressVisibility_NoAccess(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address (but no grant)
	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Visible)
	assert.Equal(t, ReasonNoAccess, resp.Reason)
	assert.Equal(t, VisibilityHidden, resp.Level)
}

func TestExplorerAPI_CheckAddressVisibility_AnonymousViewer(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create target user and link address
	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Check with unknown wallet (no DID linked)
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testUnknownWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Visible)
	assert.Equal(t, ReasonNoAccess, resp.Reason)
}

func TestExplorerAPI_CheckAddressVisibility_CaseInsensitive(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link address
	lowerAddr := "0xabcdef1234567890abcdef1234567890abcdef12"
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, lowerAddr)

	// Check with uppercase address
	upperAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+upperAddr+"?wallet="+lowerAddr, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Reason)
}

func TestExplorerAPI_CheckAddressVisibility_ExpiredGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create expired disclosure grant
	createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(-1*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Visible)
	assert.Equal(t, ReasonNoAccess, resp.Reason)
}

// ============================================================================
// Test: POST /api/v1/explorer/check-addresses
// ============================================================================

func TestExplorerAPI_BatchCheckAddresses_AnonymousViewerAllowed(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Anonymous batch check should succeed — viewer treated as anonymous
	body := BatchCheckAddressesRequest{
		Addresses: []string{testTargetAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExplorerAPI_BatchCheckAddresses_InvalidBody(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?wallet="+testViewerWallet, bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestExplorerAPI_BatchCheckAddresses_EmptyAddresses(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	body := BatchCheckAddressesRequest{
		Addresses: []string{},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?wallet="+testViewerWallet, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExplorerAPI_BatchCheckAddresses_ValidBatch(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address (no grant)
	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Batch check: own address, public address, and no-access address
	body := BatchCheckAddressesRequest{
		Addresses: []string{testViewerWallet, testPublicAddress, testTargetAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?wallet="+testViewerWallet, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchCheckAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Results, 3)

	// Own address
	assert.True(t, resp.Results[testViewerWallet].Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Results[testViewerWallet].Reason)

	// Public address
	assert.True(t, resp.Results[testPublicAddress].Visible)
	assert.Equal(t, ReasonPublicAddress, resp.Results[testPublicAddress].Reason)

	// No-access address
	assert.False(t, resp.Results[testTargetAddress].Visible)
	assert.Equal(t, ReasonNoAccess, resp.Results[testTargetAddress].Reason)
}

func TestExplorerAPI_BatchCheckAddresses_MaxLimit(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create 101 addresses (exceeds max of 100)
	addresses := make([]string, 101)
	for i := range addresses {
		// Generate a valid 40-character hex address using formatted index
		addresses[i] = fmt.Sprintf("0x%040d", i)
	}

	body := BatchCheckAddressesRequest{
		Addresses: addresses,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?wallet="+testViewerWallet, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExplorerAPI_BatchCheckAddresses_WithGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create disclosure grant
	createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(24*time.Hour))

	body := BatchCheckAddressesRequest{
		Addresses: []string{testTargetAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?wallet="+testViewerWallet, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchCheckAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Results[testTargetAddress].Visible)
	assert.Equal(t, ReasonDisclosureGrant, resp.Results[testTargetAddress].Reason)
}

// ============================================================================
// Test: calculateAddressVisibility (internal logic)
// ============================================================================

func TestCalculateAddressVisibility_AllScenarios(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	ctx := context.Background()

	tests := []struct {
		name           string
		viewerWallet   string
		targetAddress  string
		setupGrant     bool
		expectedResult AddressVisibility
	}{
		{
			name:          "own address",
			viewerWallet:  testViewerWallet,
			targetAddress: testViewerWallet,
			expectedResult: AddressVisibility{
				Address: testViewerWallet,
				Visible: true,
				Level:   VisibilityFull,
				Reason:  ReasonOwnAddress,
			},
		},
		{
			name:          "public address",
			viewerWallet:  testViewerWallet,
			targetAddress: testPublicAddress,
			expectedResult: AddressVisibility{
				Address: testPublicAddress,
				Visible: true,
				Level:   VisibilityFull,
				Reason:  ReasonPublicAddress,
			},
		},
		{
			name:          "no access without grant",
			viewerWallet:  testViewerWallet,
			targetAddress: testTargetAddress,
			setupGrant:    false,
			expectedResult: AddressVisibility{
				Address: testTargetAddress,
				Visible: false,
				Level:   VisibilityHidden,
				Reason:  ReasonNoAccess,
			},
		},
		{
			name:          "anonymous viewer sees public",
			viewerWallet:  testUnknownWallet,
			targetAddress: testPublicAddress,
			expectedResult: AddressVisibility{
				Address: testPublicAddress,
				Visible: true,
				Level:   VisibilityFull,
				Reason:  ReasonPublicAddress,
			},
		},
		{
			name:          "anonymous viewer no access",
			viewerWallet:  testUnknownWallet,
			targetAddress: testTargetAddress,
			expectedResult: AddressVisibility{
				Address: testTargetAddress,
				Visible: false,
				Level:   VisibilityHidden,
				Reason:  ReasonNoAccess,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := srv.calculateAddressVisibility(ctx, tt.viewerWallet, tt.targetAddress)
			assert.Equal(t, tt.expectedResult.Visible, result.Visible)
			assert.Equal(t, tt.expectedResult.Level, result.Level)
			assert.Equal(t, tt.expectedResult.Reason, result.Reason)
		})
	}

	// Test with grant separately (needs setup)
	t.Run("disclosed address with grant", func(t *testing.T) {
		grantID := createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(24*time.Hour))
		result := srv.calculateAddressVisibility(ctx, testViewerWallet, testTargetAddress)
		assert.True(t, result.Visible)
		assert.Equal(t, VisibilityFull, result.Level)
		assert.Equal(t, ReasonDisclosureGrant, result.Reason)
		assert.NotNil(t, result.GrantID)
		assert.Equal(t, grantID, *result.GrantID)
	})
}

// ============================================================================
// Test: Localhost Middleware
// ============================================================================

func TestExplorerAPI_LocalhostMiddleware(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Use the actual explorer routes with localhost middleware
	srv.registerExplorerRoutes(router)

	tests := []struct {
		name           string
		forwardedFor   string
		remoteAddr     string
		expectedStatus int
	}{
		{
			// External TCP peer spoofing localhost via XFF — blocked.
			// Middleware checks RemoteAddr (TCP peer), not X-Forwarded-For.
			name:           "localhost via X-Forwarded-For (blocked: external TCP peer)",
			forwardedFor:   "127.0.0.1",
			remoteAddr:     "1.2.3.4:12345",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "localhost via RemoteAddr",
			forwardedFor:   "",
			remoteAddr:     "127.0.0.1:12345",
			expectedStatus: http.StatusBadRequest, // Missing wallet param
		},
		{
			name:           "external IP forbidden",
			forwardedFor:   "8.8.8.8",
			remoteAddr:     "1.2.3.4:12345",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses", nil)
			if tt.forwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.forwardedFor)
			}
			req.RemoteAddr = tt.remoteAddr

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// ============================================================================
// Test: Grant Revocation
// ============================================================================

func TestExplorerAPI_CheckAddressVisibility_RevokedGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)
	ctx := context.Background()

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create disclosure grant
	grantID := createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(24*time.Hour))

	// Verify grant works
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonDisclosureGrant, resp.Reason)

	// Revoke the grant
	_, err := database.Conn().ExecContext(ctx,
		"UPDATE disclosure_grants SET revoked_at = NOW(), revoked_reason = 'test revocation' WHERE id = $1",
		grantID)
	require.NoError(t, err)

	// Verify grant no longer works
	req2 := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	var resp2 CheckAddressResponse
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	assert.False(t, resp2.Visible)
	assert.Equal(t, ReasonNoAccess, resp2.Reason)
}

// ============================================================================
// Test: DID-based lookups (bypassing wallet->DID lookup)
// ============================================================================

func TestExplorerAPI_GetViewableAddresses_WithDID(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link addresses
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)
	linkEthAddressToUser(t, database, testViewerDID, testViewerAddress2)

	// Query using JWT auth (no wallet)
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.ViewerWallet) // No wallet provided
	assert.Equal(t, testViewerDID, resp.ViewerDID)
	assert.Len(t, resp.OwnAddresses, 2)

	// Check that both addresses are returned
	addresses := make(map[string]bool)
	for _, a := range resp.OwnAddresses {
		addresses[a.Address] = true
	}
	assert.True(t, addresses[testViewerWallet])
	assert.True(t, addresses[testViewerAddress2])
}

func TestExplorerAPI_GetViewableAddresses_JWTTakesPrecedence(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create two users
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Query with wallet belonging to viewer but JWT of target
	// JWT should take precedence over wallet
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	addBearerToken(t, req, srv, testTargetDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, testViewerWallet, resp.ViewerWallet) // Wallet is passed through
	assert.Equal(t, testTargetDID, resp.ViewerDID)       // JWT DID takes precedence
	assert.Len(t, resp.OwnAddresses, 1)
	assert.Equal(t, testTargetAddress, resp.OwnAddresses[0].Address) // Target's addresses
}

func TestExplorerAPI_CheckAddressVisibility_WithDID(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link address
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Check visibility of own address using JWT auth
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testViewerWallet, nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Reason)
	assert.Equal(t, VisibilityFull, resp.Level)
}

func TestExplorerAPI_CheckAddressVisibility_DIDWithGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user (no wallet linked - DID-only scenario)
	createTestUserForExplorer(t, database, testViewerDID)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create disclosure grant
	grantID := createDisclosureGrant(t, database, testViewerDID, targetUserID, time.Now().Add(24*time.Hour))

	// Check using JWT auth (no wallet)
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress, nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Visible)
	assert.Equal(t, ReasonDisclosureGrant, resp.Reason)
	assert.Equal(t, VisibilityFull, resp.Level)
	assert.NotNil(t, resp.GrantID)
	assert.Equal(t, grantID, *resp.GrantID)
}

func TestExplorerAPI_BatchCheckAddresses_WithDIDInQueryString(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Batch check using JWT auth
	body := BatchCheckAddressesRequest{
		Addresses: []string{testViewerWallet, testPublicAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchCheckAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Results, 2)

	// Own address
	assert.True(t, resp.Results[testViewerWallet].Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Results[testViewerWallet].Reason)

	// Public address
	assert.True(t, resp.Results[testPublicAddress].Visible)
	assert.Equal(t, ReasonPublicAddress, resp.Results[testPublicAddress].Reason)
}

func TestExplorerAPI_BatchCheckAddresses_WithJWTAuth(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Batch check using JWT auth
	body := BatchCheckAddressesRequest{
		Addresses: []string{testViewerWallet, testPublicAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchCheckAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Results, 2)

	// Own address
	assert.True(t, resp.Results[testViewerWallet].Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Results[testViewerWallet].Reason)
}

func TestExplorerAPI_BatchCheckAddresses_DIDQueryParamIgnored(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create two users
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Pass ?did=targetDID in query string WITHOUT JWT — should be treated as anonymous
	body := BatchCheckAddressesRequest{
		Addresses: []string{testTargetAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?did="+testTargetDID, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchCheckAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Without JWT, ?did= is ignored — viewer is anonymous, target address is not "own"
	assert.False(t, resp.Results[testTargetAddress].Visible)
}

// ============================================================================
// Test: explorer.GenerateAddressID() - Address ID Generation
// ============================================================================

func TestGenerateAddressID_Consistency(t *testing.T) {
	// Same inputs should always produce same output
	address := "0x1234567890abcdef1234567890abcdef12345678"
	grantID := "grant-abc-123"

	id1 := explorer.GenerateAddressID(address, grantID)
	id2 := explorer.GenerateAddressID(address, grantID)

	assert.Equal(t, id1, id2, "generateAddressID should produce consistent results")
}

func TestGenerateAddressID_Uniqueness(t *testing.T) {
	tests := []struct {
		name     string
		address1 string
		grant1   string
		address2 string
		grant2   string
	}{
		{
			name:     "different addresses same grant",
			address1: "0x1111111111111111111111111111111111111111",
			grant1:   "grant-123",
			address2: "0x2222222222222222222222222222222222222222",
			grant2:   "grant-123",
		},
		{
			name:     "same address different grants",
			address1: "0x1111111111111111111111111111111111111111",
			grant1:   "grant-123",
			address2: "0x1111111111111111111111111111111111111111",
			grant2:   "grant-456",
		},
		{
			name:     "both different",
			address1: "0x1111111111111111111111111111111111111111",
			grant1:   "grant-123",
			address2: "0x2222222222222222222222222222222222222222",
			grant2:   "grant-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1 := explorer.GenerateAddressID(tt.address1, tt.grant1)
			id2 := explorer.GenerateAddressID(tt.address2, tt.grant2)
			assert.NotEqual(t, id1, id2, "Different inputs should produce different IDs")
		})
	}
}

func TestGenerateAddressID_CaseInsensitive(t *testing.T) {
	// Address case should not affect the ID (addresses are normalized to lowercase)
	lowerAddr := "0xabcdef1234567890abcdef1234567890abcdef12"
	upperAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
	grantID := "grant-123"

	idLower := explorer.GenerateAddressID(lowerAddr, grantID)
	idUpper := explorer.GenerateAddressID(upperAddr, grantID)

	assert.Equal(t, idLower, idUpper, "Address IDs should be case-insensitive")
}

func TestGenerateAddressID_NoAddressLeakage(t *testing.T) {
	// The generated ID should not contain the original address
	address := "0xdeadbeef12345678deadbeef12345678deadbeef"
	grantID := "grant-xyz"

	id := explorer.GenerateAddressID(address, grantID)

	// ID should not contain address parts
	assert.NotContains(t, id, "deadbeef")
	assert.NotContains(t, id, "12345678")
	assert.NotContains(t, id, "0x")

	// ID should be hex encoded (16 chars from 8 bytes)
	assert.Len(t, id, 16, "Address ID should be 16 hex characters")
}

func TestGenerateAddressID_Format(t *testing.T) {
	id := explorer.GenerateAddressID("0x1234567890abcdef1234567890abcdef12345678", "grant-123")

	// Should be valid hex
	for _, c := range id {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"ID should only contain valid hex characters")
	}
}

// ============================================================================
// Test: explorer.GeneratePseudonym() - Pseudonym Generation
// ============================================================================

func TestGeneratePseudonym_Consistency(t *testing.T) {
	address := "0x1234567890abcdef1234567890abcdef12345678"

	p1 := explorer.GeneratePseudonym(address)
	p2 := explorer.GeneratePseudonym(address)

	assert.Equal(t, p1, p2, "generatePseudonym should produce consistent results")
}

func TestGeneratePseudonym_Format(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected string
	}{
		{
			name:     "address starting with 0x1234",
			address:  "0x1234567890abcdef1234567890abcdef12345678",
			expected: "Address-BCDE", // 1->B, 2->C, 3->D, 4->E
		},
		{
			name:     "address starting with 0xABCD",
			address:  "0xABCD567890abcdef1234567890abcdef12345678",
			expected: "Address-KLMN", // A->K, B->L, C->M, D->N
		},
		{
			name:     "address starting with 0x0000",
			address:  "0x0000567890abcdef1234567890abcdef12345678",
			expected: "Address-AAAA", // 0->A, 0->A, 0->A, 0->A
		},
		{
			name:     "address starting with 0xFFFF",
			address:  "0xFFFF567890abcdef1234567890abcdef12345678",
			expected: "Address-PPPP", // F->P, F->P, F->P, F->P
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := explorer.GeneratePseudonym(tt.address)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGeneratePseudonym_NoAddressLeakage(t *testing.T) {
	address := "0xdeadbeef12345678deadbeef12345678deadbeef"
	pseudonym := explorer.GeneratePseudonym(address)

	// Pseudonym should not contain address parts
	assert.NotContains(t, pseudonym, "dead")
	assert.NotContains(t, pseudonym, "beef")
	assert.NotContains(t, pseudonym, "0x")

	// Should have "Address-" prefix
	assert.True(t, len(pseudonym) > 8)
	assert.Equal(t, "Address-", pseudonym[:8])
}

func TestGeneratePseudonym_DifferentAddresses(t *testing.T) {
	addr1 := "0x1111111111111111111111111111111111111111"
	addr2 := "0x2222222222222222222222222222222222222222"
	addr3 := "0xAAAA111111111111111111111111111111111111"

	p1 := explorer.GeneratePseudonym(addr1)
	p2 := explorer.GeneratePseudonym(addr2)
	p3 := explorer.GeneratePseudonym(addr3)

	assert.NotEqual(t, p1, p2)
	assert.NotEqual(t, p1, p3)
	assert.NotEqual(t, p2, p3)
}

func TestGeneratePseudonym_ShortAddress(t *testing.T) {
	// Edge case: address too short
	shortAddr := "0x12"
	result := explorer.GeneratePseudonym(shortAddr)
	assert.Equal(t, "Address-Unknown", result)

	// Very short
	veryShort := "0x"
	result2 := explorer.GeneratePseudonym(veryShort)
	assert.Equal(t, "Address-Unknown", result2)
}

func TestGeneratePseudonym_CaseInsensitive(t *testing.T) {
	lower := "0xabcd567890abcdef1234567890abcdef12345678"
	upper := "0xABCD567890ABCDEF1234567890ABCDEF12345678"

	pLower := explorer.GeneratePseudonym(lower)
	pUpper := explorer.GeneratePseudonym(upper)

	assert.Equal(t, pLower, pUpper, "Pseudonyms should be case-insensitive")
}

// ============================================================================
// Test: getDisclosedAddressesForViewer() - Disclosure Level Redaction
// ============================================================================

// createDisclosureGrantWithLevel creates a grant with a specific disclosure level
func createDisclosureGrantWithLevel(t *testing.T, database *db.DB, requesterDID, targetUserID string, level disclosure.DisclosureLevel, expiresAt time.Time) string {
	ctx := context.Background()

	// Create default org if not exists
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// Create disclosure request with scope
	requestID := uuid.New().String()
	scope := fmt.Sprintf(`{"disclosure_level":"%s"}`, level)
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5, 'Test grant', 'approved', NOW())`,
		requestID, requesterDID, targetUserID, defaultOrgID, scope)
	require.NoError(t, err)

	// Create grant with disclosure level scope
	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, NOW(), $5)`,
		grantID, requestID, "test-hash-"+grantID, scope, expiresAt)
	require.NoError(t, err)

	return grantID
}

func TestGetDisclosedAddressesForViewer_FullDisclosure(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create full disclosure grant
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should have 1 disclosed address with REAL address visible
	require.Len(t, resp.DisclosedAddresses, 1)
	disclosed := resp.DisclosedAddresses[0]

	assert.Equal(t, testTargetAddress, disclosed.Address, "Full disclosure should show real address")
	assert.Equal(t, "full", disclosed.DisclosureLevel)
	assert.NotEmpty(t, disclosed.AddressID)
	assert.Equal(t, testTargetDID, disclosed.OwnerDID)
}

func TestGetDisclosedAddressesForViewer_PseudonymousDisclosure(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create pseudonymous disclosure grant
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should have 1 disclosed address with PSEUDONYM (not real address)
	require.Len(t, resp.DisclosedAddresses, 1)
	disclosed := resp.DisclosedAddresses[0]

	// SECURITY: Real address should NOT be returned
	assert.NotEqual(t, testTargetAddress, disclosed.Address, "Pseudonymous should NOT show real address")
	assert.True(t, strings.HasPrefix(disclosed.Address, "Address-"), "Should show pseudonym")
	assert.Equal(t, "pseudonymous", disclosed.DisclosureLevel)
	assert.NotEmpty(t, disclosed.AddressID)
	assert.Nil(t, disclosed.ENSName, "ENS name should not be included for pseudonymous")
}

func TestGetDisclosedAddressesForViewer_RedactedDisclosure(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create redacted disclosure grant
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureRedacted, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should have 1 disclosed address with [REDACTED]
	require.Len(t, resp.DisclosedAddresses, 1)
	disclosed := resp.DisclosedAddresses[0]

	// SECURITY: Real address should NOT be returned
	assert.NotEqual(t, testTargetAddress, disclosed.Address, "Redacted should NOT show real address")
	assert.Equal(t, "[REDACTED]", disclosed.Address, "Should show [REDACTED] placeholder")
	assert.Equal(t, "redacted", disclosed.DisclosureLevel)
	assert.NotEmpty(t, disclosed.AddressID)
	assert.Nil(t, disclosed.ENSName, "ENS name should not be included for redacted")
}

func TestCheckAddressVisibility_PseudonymousGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create pseudonymous disclosure grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Visible)
	assert.Equal(t, VisibilityPseudonymous, resp.Level)
	assert.Equal(t, ReasonDisclosureGrant, resp.Reason)
	assert.NotNil(t, resp.Pseudonym)
	assert.True(t, strings.HasPrefix(*resp.Pseudonym, "Address-"))
	assert.NotNil(t, resp.GrantID)
	assert.Equal(t, grantID, *resp.GrantID)
}

func TestCheckAddressVisibility_RedactedGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user and link wallet
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create redacted disclosure grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureRedacted, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CheckAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Visible)
	assert.Equal(t, VisibilityRedacted, resp.Level)
	assert.Equal(t, ReasonDisclosureGrant, resp.Reason)
	assert.Nil(t, resp.Pseudonym, "Redacted should not have pseudonym")
	assert.NotNil(t, resp.GrantID)
	assert.Equal(t, grantID, *resp.GrantID)
}

// ============================================================================
// Test: resolveAddressID() - Address Resolution Endpoint
// ============================================================================

// setupExplorerRouterWithResolve creates a router with all explorer routes including resolve
func setupExplorerRouterWithResolve(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Explorer routes without localhost middleware for unit tests
	explorer := router.Group("/api/v1/explorer")
	explorer.GET("/viewable-addresses", srv.getViewableAddresses)
	explorer.GET("/check-address/:address", srv.checkAddressVisibility)
	explorer.POST("/check-addresses", srv.batchCheckAddresses)
	explorer.GET("/grant/:grant_id/resolve/:address_id", srv.resolveAddressID)

	return router
}

func TestResolveAddressID_Success(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	// Get address ID from viewable-addresses
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ResolveAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, testTargetAddress, resp.RealAddress)
	assert.Equal(t, "full", resp.DisclosureLevel)
	assert.Equal(t, grantID, resp.GrantID)
}

func TestResolveAddressID_PseudonymousIncludesPseudonym(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create pseudonymous grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ResolveAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, testTargetAddress, resp.RealAddress)
	assert.Equal(t, "pseudonymous", resp.DisclosureLevel)
	assert.NotEmpty(t, resp.Pseudonym, "Pseudonymous should include pseudonym")
	assert.True(t, strings.HasPrefix(resp.Pseudonym, "Address-"))
}

func TestResolveAddressID_InvalidGrantID(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/invalid-grant-id/resolve/some-address-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "grant not found")
}

func TestResolveAddressID_InvalidAddressID(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	// Use wrong address ID
	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/resolve/invalid-address-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "address not found")
}

func TestResolveAddressID_ExpiredGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create EXPIRED grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(-1*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "expired")
}

func TestResolveAddressID_RevokedGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)
	ctx := context.Background()

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create grant (valid expiry)
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	// Revoke the grant
	_, err := database.Conn().ExecContext(ctx,
		"UPDATE disclosure_grants SET revoked_at = NOW(), revoked_reason = 'test revocation' WHERE id = $1",
		grantID)
	require.NoError(t, err)

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "revoked")
}

func TestResolveAddressID_MissingParams(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouterWithResolve(srv)

	// Missing address_id
	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/some-grant-id/resolve/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should get 404 due to route not matching (empty address_id)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// Test: Security - Address Leakage Prevention
// ============================================================================

func TestSecurity_PseudonymousDoesNotLeakRealAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address with unique identifier
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	sensitiveAddress := "0xSensitive1234567890123456789012345678"
	linkEthAddressToUser(t, database, testTargetDID, sensitiveAddress)

	// Create pseudonymous grant
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Response body should NOT contain the sensitive address
	body := w.Body.String()
	assert.NotContains(t, body, sensitiveAddress, "SECURITY VIOLATION: Real address leaked in pseudonymous mode")
	assert.NotContains(t, body, "Sensitive1234", "SECURITY VIOLATION: Real address parts leaked")
}

func TestSecurity_RedactedDoesNotLeakRealAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address with unique identifier
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	sensitiveAddress := "0xSecret99999999999999999999999999999999"
	linkEthAddressToUser(t, database, testTargetDID, sensitiveAddress)

	// Create redacted grant
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureRedacted, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Response body should NOT contain the sensitive address
	body := w.Body.String()
	assert.NotContains(t, body, sensitiveAddress, "SECURITY VIOLATION: Real address leaked in redacted mode")
	assert.NotContains(t, body, "Secret9999", "SECURITY VIOLATION: Real address parts leaked")
	assert.Contains(t, body, "[REDACTED]", "Should show redacted placeholder")
}

// ============================================================================
// Test: Edge Cases
// ============================================================================

func TestEdgeCase_NoAuthParams(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Query with no auth parameters should be rejected
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEdgeCase_EmptyWallet(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Query with empty wallet should be rejected
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEdgeCase_NullAddressInGrant(t *testing.T) {
	// This tests the scenario where a user might have no linked addresses
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user WITHOUT linking any addresses
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)

	// Create grant
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should have 0 disclosed addresses (target has no addresses)
	assert.Len(t, resp.DisclosedAddresses, 0)
}

func TestEdgeCase_MultipleAddressesSameGrant(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link MULTIPLE addresses
	// Note: Use different prefixes so pseudonyms are unique (first 4 hex chars determine pseudonym)
	// Avoid addresses that conflict with testViewerWallet (0x1111...) or testTargetAddress (0x2222...)
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	addr1 := "0xaaaa111111111111111111111111111111111111"
	addr2 := "0xbbbb222222222222222222222222222222222222"
	addr3 := "0xcccc333333333333333333333333333333333333"
	linkEthAddressToUser(t, database, testTargetDID, addr1)
	linkEthAddressToUser(t, database, testTargetDID, addr2)
	linkEthAddressToUser(t, database, testTargetDID, addr3)

	// Create single grant (should cover all addresses)
	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should have 3 disclosed addresses, all pseudonymous
	assert.Len(t, resp.DisclosedAddresses, 3)

	// All should be pseudonymous and have different pseudonyms
	pseudonyms := make(map[string]bool)
	for _, disclosed := range resp.DisclosedAddresses {
		assert.True(t, strings.HasPrefix(disclosed.Address, "Address-"))
		assert.Equal(t, "pseudonymous", disclosed.DisclosureLevel)
		pseudonyms[disclosed.Address] = true
	}

	// All pseudonyms should be unique (different addresses = different pseudonyms)
	assert.Len(t, pseudonyms, 3, "Each address should have unique pseudonym")
}

func TestEdgeCase_ConcurrentAccess(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer and target
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID, disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	// Make concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// ============================================================================
// Helpers: Org contract fixture for server-level tests
// ============================================================================

// registerOrgContract inserts an org, group, contract, and contract_grant into the
// privacy-proxy DB. Returns the group ID so callers can add members.
func registerOrgContract(t *testing.T, database *db.DB, contractAddr string) (groupID string) {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "srv-org-"+orgID[:8], "Server Test Org")
	require.NoError(t, err)

	groupID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)

	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		contractID, orgID, contractAddr, "Server Test Private Contract")
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	return groupID
}

// addUserToGroup adds an existing user (by internal ID) to a group.
func addUserToGroup(t *testing.T, database *db.DB, userID, groupID string) {
	t.Helper()
	_, err := database.Conn().ExecContext(context.Background(),
		"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')",
		uuid.New().String(), userID, groupID)
	require.NoError(t, err)
}

// ============================================================================
// Test: org contract visibility via check-address endpoint
// ============================================================================

func TestExplorerAPI_CheckAddressVisibility_OrgContract_NonMember(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	const orgAddr = "0xaaaa000000000000000000000000000000000011"
	registerOrgContract(t, database, orgAddr)

	// Non-member viewer exists in DB but has no group membership
	createTestUserForExplorer(t, database, testViewerDID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+orgAddr, nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp CheckAddressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.False(t, resp.Visible, "non-member must not see org contract")
	// Org contracts use VisibilityRedacted (not Hidden) so transactions aren't silently
	// dropped from global lists — the contract's on-chain existence is visible, only the
	// identity is protected. This matches the RedactionEngine's GetBatchVisibility behavior.
	assert.Equal(t, VisibilityRedacted, resp.Level)
	assert.Equal(t, ReasonNoAccess, resp.Reason)
}

func TestExplorerAPI_CheckAddressVisibility_OrgContract_Member(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	const orgAddr = "0xaaaa000000000000000000000000000000000012"
	const memberDID = "did:privado:org_member_check"
	groupID := registerOrgContract(t, database, orgAddr)

	memberID := createTestUserForExplorer(t, database, memberDID)
	addUserToGroup(t, database, memberID, groupID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+orgAddr, nil)
	addBearerToken(t, req, srv, memberDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp CheckAddressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.True(t, resp.Visible, "group member must see their org contract")
	assert.Equal(t, VisibilityFull, resp.Level)
	assert.Equal(t, ReasonRBACGroupMember, resp.Reason)
}

func TestExplorerAPI_CheckAddressVisibility_OrgContract_Anonymous(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	const orgAddr = "0xaaaa000000000000000000000000000000000013"
	registerOrgContract(t, database, orgAddr)

	// No DID provided — anonymous viewer
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+orgAddr+"?wallet="+testUnknownWallet, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp CheckAddressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.False(t, resp.Visible, "anonymous viewer must not see org contract")
	assert.Equal(t, VisibilityRedacted, resp.Level)
}

// TestExplorerAPI_OrgContract_DoesNotLeakInBatchCheck verifies that a batch-check
// correctly hides an org contract from non-members and reveals it to members.
func TestExplorerAPI_OrgContract_DoesNotLeakInBatchCheck(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGrp := router.Group("/api/v1/explorer")
	explorerGrp.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGrp.GET("/check-address/:address", srv.checkAddressVisibility)
	explorerGrp.POST("/check-addresses", srv.batchCheckAddresses)

	const orgAddr = "0xaaaa000000000000000000000000000000000014"
	const publicAddr = "0x9999000000000000000000000000000000000099"
	const outsiderDID = "did:privado:batch_outsider"
	const memberDID2 = "did:privado:batch_member2"

	groupID := registerOrgContract(t, database, orgAddr)
	createTestUserForExplorer(t, database, outsiderDID)
	memberID := createTestUserForExplorer(t, database, memberDID2)
	addUserToGroup(t, database, memberID, groupID)

	body := `{"addresses":["` + orgAddr + `","` + publicAddr + `"]}`

	t.Run("outsider batch check hides org contract", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addBearerToken(t, req, srv, outsiderDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var resp BatchCheckAddressesResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		orgVis, ok := resp.Results[orgAddr]
		require.True(t, ok)
		assert.False(t, orgVis.Visible, "outsider must not see org contract")
		assert.Equal(t, VisibilityRedacted, orgVis.Level)

		pubVis, ok := resp.Results[publicAddr]
		require.True(t, ok)
		assert.True(t, pubVis.Visible, "public address must be visible to outsider")
	})

	t.Run("member batch check reveals org contract", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addBearerToken(t, req, srv, memberDID2)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var resp BatchCheckAddressesResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		orgVis, ok := resp.Results[orgAddr]
		require.True(t, ok)
		assert.True(t, orgVis.Visible, "member must see their org contract")
		assert.Equal(t, VisibilityFull, orgVis.Level)
	})
}

// ============================================================================
// Transaction redaction integration tests
//
// These tests exercise the full stack: HTTP endpoint → RedactionEngine →
// GetBatchVisibility (real PostgreSQL). They would have caught the
// "Private → Private" privacy leak where transactions between two
// non-identifiable parties were shown instead of being dropped.
// ============================================================================

// explorerBlockCounter provides unique block numbers across parallel tests.
var explorerBlockCounter int64 = 5000

// explorerSchema is the minimal set of explorer tables needed for transaction tests.
const explorerSchema = `
CREATE TABLE IF NOT EXISTS blocks (
    number BIGINT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    parent_hash TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    gas_used BIGINT NOT NULL,
    gas_limit BIGINT NOT NULL,
    base_fee_per_gas BIGINT,
    transaction_count INT NOT NULL,
    size BIGINT DEFAULT 0,
    difficulty TEXT DEFAULT '0',
    total_difficulty TEXT DEFAULT '0',
    nonce TEXT DEFAULT '0x0000000000000000',
    miner TEXT,
    extra_data TEXT,
    state_root TEXT,
    transactions_root TEXT,
    receipts_root TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    hash TEXT PRIMARY KEY,
    block_number BIGINT NOT NULL REFERENCES blocks(number) ON DELETE CASCADE,
    tx_index INT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT,
    value NUMERIC(78, 0) NOT NULL,
    gas_used BIGINT NOT NULL,
    gas_price BIGINT NOT NULL,
    gas_limit BIGINT,
    max_fee_per_gas BIGINT,
    max_priority_fee_per_gas BIGINT,
    nonce BIGINT,
    tx_type SMALLINT DEFAULT 0,
    input_data TEXT,
    status SMALLINT NOT NULL,
    error TEXT,
    revert_reason TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
`

// setupTestServerForExplorerTransactions creates a test server with explorer store
// and redaction engine configured, using a real PostgreSQL database.
func setupTestServerForExplorerTransactions(t *testing.T) (*Server, *db.DB, *sql.DB) {
	t.Helper()

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, db.ResetTestDatabase(database))

	// Create explorer tables in the same database and truncate for test isolation
	// (CI uses a shared PostgreSQL instance, so data from prior tests may exist).
	_, err = database.Conn().ExecContext(context.Background(), explorerSchema)
	require.NoError(t, err, "failed to create explorer schema")
	_, err = database.Conn().ExecContext(context.Background(),
		"TRUNCATE transactions, blocks CASCADE")
	require.NoError(t, err, "failed to truncate explorer tables")

	// Open a separate connection for the explorer store.
	explorerStore, err := explorer.NewStore(dbURL)
	require.NoError(t, err)

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		VerifierID:  "did:privado:verifier:test",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	srv := &Server{
		db:                database,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbac.NewAccessController(database, 5*time.Minute),
		disclosureService: disclosure.NewService(database),
		config:            cfg,
		explorerStore:     explorerStore,
		explorerRedactor:  explorer.NewRedactionEngine(explorerStore, database),
	}

	t.Cleanup(func() {
		explorerStore.Close()
		srv.db.Close()
	})

	return srv, database, database.Conn()
}

// setupExplorerTransactionsRouter creates a gin router with the transactions endpoint.
func setupExplorerTransactionsRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/transactions", srv.getExplorerTransactions)
	return router
}

// seedExplorerBlock inserts a block into the explorer tables and returns its number.
func seedExplorerBlock(t *testing.T, conn *sql.DB) int64 {
	t.Helper()
	num := atomic.AddInt64(&explorerBlockCounter, 1)
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		 VALUES ($1, $2, $3, $4, 21000, 30000000, 1)`,
		num, fmt.Sprintf("0xblock%d", num), fmt.Sprintf("0xparent%d", num-1), time.Now().Unix())
	require.NoError(t, err)
	return num
}

// seedExplorerTransaction inserts a transaction into the explorer tables.
func seedExplorerTransaction(t *testing.T, conn *sql.DB, blockNum int64, hash, from, to string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, nonce, status, input_data)
		 VALUES ($1, $2, 0, $3, $4, 0, 21000, 1000000000, 1, 1, '0x')`,
		hash, blockNum, from, to)
	require.NoError(t, err)
}

// setupOrgContractInPrivacyProxy creates an org, group, contract, and contract_grant
// in the privacy-proxy database. Returns the group ID for membership assignment.
func setupOrgContractInPrivacyProxy(t *testing.T, database *db.DB, contractAddr string) string {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "txtest-org-"+orgID[:8], "Tx Test Org")
	require.NoError(t, err)

	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)

	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		contractID, orgID, contractAddr, "Test Contract")
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	return groupID
}

// parseTransactionsResponse unmarshals the JSON response body into a slice of
// explorer.Transaction.
func parseTransactionsResponse(t *testing.T, body []byte) []explorer.Transaction {
	t.Helper()
	var txs []explorer.Transaction
	require.NoError(t, json.Unmarshal(body, &txs))
	return txs
}

// TestExplorerTransactions_BothOwnedAddresses_AnonymousViewerSeesNothing verifies
// that a transaction between two owned (private) addresses is completely dropped
// for an anonymous viewer. Both addresses resolve to VisibilityHidden, so the
// transaction must not appear at all — showing "[PRIVATE] -> [PRIVATE]" would
// leak transaction existence and timing.
func TestExplorerTransactions_BothOwnedAddresses_AnonymousViewerSeesNothing(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupExplorerTransactionsRouter(srv)

	// Create two users and link their addresses.
	addrA := "0xaaaa000000000000000000000000000000000001"
	addrB := "0xbbbb000000000000000000000000000000000002"

	createTestUserForExplorer(t, database, "did:a:hidden")
	linkEthAddressToUser(t, database, "did:a:hidden", addrA)

	createTestUserForExplorer(t, database, "did:b:hidden")
	linkEthAddressToUser(t, database, "did:b:hidden", addrB)

	// Seed a transaction from A to B.
	blockNum := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, blockNum, "0xtx_hidden_hidden_1", addrA, addrB)

	// Anonymous request (no wallet/did param).
	req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	txs := parseTransactionsResponse(t, w.Body.Bytes())
	assert.Empty(t, txs, "transaction between two Hidden addresses must be dropped for anonymous viewer")
}

// TestExplorerTransactions_OwnedPlusOrgContract_AnonymousViewerSeesNothing verifies
// that a transaction between a Hidden address (owned by a user) and a Redacted
// address (org-owned contract) is dropped for an anonymous viewer. This was the
// core "Private -> Private" bug: org-owned contracts get VisibilityRedacted (not
// VisibilityHidden), and the old drop check only matched Hidden+Hidden.
func TestExplorerTransactions_OwnedPlusOrgContract_AnonymousViewerSeesNothing(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupExplorerTransactionsRouter(srv)

	// Create a user with a linked (private) address.
	addrUser := "0xaaaa000000000000000000000000000000000011"
	createTestUserForExplorer(t, database, "did:user:orgtest")
	linkEthAddressToUser(t, database, "did:user:orgtest", addrUser)

	// Create an org-owned contract in the privacy-proxy DB.
	addrContract := "0xcccc000000000000000000000000000000000011"
	setupOrgContractInPrivacyProxy(t, database, addrContract)

	// Seed a transaction from the user to the org contract.
	blockNum := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, blockNum, "0xtx_hidden_redacted_1", addrUser, addrContract)

	// Anonymous request.
	req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	txs := parseTransactionsResponse(t, w.Body.Bytes())
	assert.Empty(t, txs, "transaction between Hidden user and Redacted org contract must be dropped for anonymous viewer")
}

// TestExplorerTransactions_ParticipantSeesOwnTransaction verifies that a
// participant in a transaction can see it with full addresses, even when both
// parties are private to everyone else.
func TestExplorerTransactions_ParticipantSeesOwnTransaction(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupExplorerTransactionsRouter(srv)

	addrA := "0xaaaa000000000000000000000000000000000021"
	addrB := "0xbbbb000000000000000000000000000000000022"
	didA := "did:a:participant"
	didB := "did:b:participant"

	createTestUserForExplorer(t, database, didA)
	linkEthAddressToUser(t, database, didA, addrA)

	createTestUserForExplorer(t, database, didB)
	linkEthAddressToUser(t, database, didB, addrB)

	blockNum := seedExplorerBlock(t, conn)
	txHash := "0xtx_participant_1"
	seedExplorerTransaction(t, conn, blockNum, txHash, addrA, addrB)

	// Request as participant A.
	req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
	addBearerToken(t, req, srv, didA)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	txs := parseTransactionsResponse(t, w.Body.Bytes())
	require.Len(t, txs, 1, "participant must see their own transaction")
	assert.Equal(t, txHash, txs[0].Hash)
	// Participant override reveals both addresses.
	assert.Equal(t, addrA, strings.ToLower(txs[0].From))
	require.NotNil(t, txs[0].To)
	assert.Equal(t, addrB, strings.ToLower(*txs[0].To))
}

// TestExplorerTransactions_ThirdPartyWithGrantSeesGrantedParty verifies that
// when viewer A has a disclosure grant on user B, a transaction from B to C
// (where C is private) is shown with B's address visible and C masked as
// [PRIVATE]. The transaction is kept because one side (B) is identifiable.
func TestExplorerTransactions_ThirdPartyWithGrantSeesGrantedParty(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupExplorerTransactionsRouter(srv)

	addrA := "0xaaaa000000000000000000000000000000000031"
	addrB := "0xbbbb000000000000000000000000000000000032"
	addrC := "0xcccc000000000000000000000000000000000033"
	didA := "did:a:grantviewer"
	didB := "did:b:granttarget"
	didC := "did:c:noaccess"

	// Create viewer A.
	createTestUserForExplorer(t, database, didA)
	linkEthAddressToUser(t, database, didA, addrA)

	// Create target B (whose addresses A can see via grant).
	targetUserID := createTestUserForExplorer(t, database, didB)
	linkEthAddressToUser(t, database, didB, addrB)

	// Create user C (no grant from A).
	createTestUserForExplorer(t, database, didC)
	linkEthAddressToUser(t, database, didC, addrC)

	// Grant A full disclosure on B.
	createDisclosureGrant(t, database, didA, targetUserID, time.Now().Add(24*time.Hour))

	// Seed a transaction from B to C.
	blockNum := seedExplorerBlock(t, conn)
	txHash := "0xtx_grant_1"
	seedExplorerTransaction(t, conn, blockNum, txHash, addrB, addrC)

	// Request as viewer A.
	req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
	addBearerToken(t, req, srv, didA)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	txs := parseTransactionsResponse(t, w.Body.Bytes())
	require.Len(t, txs, 1, "transaction should be kept: B is identifiable via grant")
	assert.Equal(t, txHash, txs[0].Hash)
	// B's address is visible (grant), C is masked.
	assert.Equal(t, addrB, strings.ToLower(txs[0].From))
	require.NotNil(t, txs[0].To)
	assert.Equal(t, "[PRIVATE]", *txs[0].To)
}

// TestExplorerTransactions_PublicAddresses_VisibleToAll verifies that
// transactions between public (unowned) addresses are fully visible to everyone,
// including anonymous viewers.
func TestExplorerTransactions_PublicAddresses_VisibleToAll(t *testing.T) {
	srv, _, conn := setupTestServerForExplorerTransactions(t)
	router := setupExplorerTransactionsRouter(srv)

	// These addresses are not linked to any user — they are public.
	addrE := "0xeeee000000000000000000000000000000000041"
	addrF := "0xffff000000000000000000000000000000000042"

	blockNum := seedExplorerBlock(t, conn)
	txHash := "0xtx_public_1"
	seedExplorerTransaction(t, conn, blockNum, txHash, addrE, addrF)

	// Anonymous request.
	req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	txs := parseTransactionsResponse(t, w.Body.Bytes())
	require.Len(t, txs, 1, "transaction between public addresses must be visible")
	assert.Equal(t, txHash, txs[0].Hash)
	assert.Equal(t, addrE, strings.ToLower(txs[0].From))
	require.NotNil(t, txs[0].To)
	assert.Equal(t, addrF, strings.ToLower(*txs[0].To))
}
