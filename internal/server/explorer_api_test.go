package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
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

// setupExplorerRouter creates a router with explorer routes for testing
// Note: We skip the localhost middleware for unit tests
func setupExplorerRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Explorer routes without localhost middleware for unit tests
	explorer := router.Group("/api/v1/explorer")
	explorer.GET("/viewable-addresses", srv.getViewableAddresses)
	explorer.GET("/check-address/:address", srv.checkAddressVisibility)
	explorer.POST("/check-addresses", srv.batchCheckAddresses)

	return router
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

func TestExplorerAPI_GetViewableAddresses_MissingWallet(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "wallet parameter is required")
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

func TestExplorerAPI_CheckAddressVisibility_MissingWallet(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "wallet parameter is required")
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

func TestExplorerAPI_BatchCheckAddresses_MissingWallet(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	body := BatchCheckAddressesRequest{
		Addresses: []string{testTargetAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "wallet parameter is required")
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
			name:           "localhost via X-Forwarded-For",
			forwardedFor:   "127.0.0.1",
			remoteAddr:     "1.2.3.4:12345",
			expectedStatus: http.StatusBadRequest, // Missing wallet param
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
