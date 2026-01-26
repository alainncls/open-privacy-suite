package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func TestExplorerAPI_GetViewableAddresses_MissingWalletAndDID(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "either wallet or did parameter is required")
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
	assert.Contains(t, w.Body.String(), "either wallet or did parameter is required")
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

func TestExplorerAPI_BatchCheckAddresses_MissingWalletAndDID(t *testing.T) {
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
	assert.Contains(t, w.Body.String(), "either wallet or did parameter is required")
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

	// Query using DID directly (no wallet)
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?did="+testViewerDID, nil)
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

func TestExplorerAPI_GetViewableAddresses_DIDTakesPrecedence(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create two users
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Query with wallet belonging to viewer but DID of target
	// DID should take precedence
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?wallet="+testViewerWallet+"&did="+testTargetDID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ViewableAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, testViewerWallet, resp.ViewerWallet) // Wallet is passed through
	assert.Equal(t, testTargetDID, resp.ViewerDID)       // DID takes precedence
	assert.Len(t, resp.OwnAddresses, 1)
	assert.Equal(t, testTargetAddress, resp.OwnAddresses[0].Address) // Target's addresses
}

func TestExplorerAPI_CheckAddressVisibility_WithDID(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create user and link address
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Check visibility of own address using DID directly
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testViewerWallet+"?did="+testViewerDID, nil)
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

	// Check using DID directly (no wallet)
	req := httptest.NewRequest("GET", "/api/v1/explorer/check-address/"+testTargetAddress+"?did="+testViewerDID, nil)
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

	// Batch check using DID in query string
	body := BatchCheckAddressesRequest{
		Addresses: []string{testViewerWallet, testPublicAddress},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?did="+testViewerDID, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
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

func TestExplorerAPI_BatchCheckAddresses_WithDIDInBody(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Batch check using DID in request body
	body := BatchCheckAddressesRequest{
		Addresses: []string{testViewerWallet, testPublicAddress},
		DID:       testViewerDID,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
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

func TestExplorerAPI_BatchCheckAddresses_BodyDIDTakesPrecedence(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create two users
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Query string has viewerDID, body has targetDID - body should take precedence
	body := BatchCheckAddressesRequest{
		Addresses: []string{testTargetAddress},
		DID:       testTargetDID,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses?did="+testViewerDID, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchCheckAddressesResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Target's address should be their own (body DID = targetDID)
	assert.True(t, resp.Results[testTargetAddress].Visible)
	assert.Equal(t, ReasonOwnAddress, resp.Results[testTargetAddress].Reason)
}

// ============================================================================
// Test: generateAddressID() - Address ID Generation
// ============================================================================

func TestGenerateAddressID_Consistency(t *testing.T) {
	// Same inputs should always produce same output
	address := "0x1234567890abcdef1234567890abcdef12345678"
	grantID := "grant-abc-123"

	id1 := generateAddressID(address, grantID)
	id2 := generateAddressID(address, grantID)

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
			id1 := generateAddressID(tt.address1, tt.grant1)
			id2 := generateAddressID(tt.address2, tt.grant2)
			assert.NotEqual(t, id1, id2, "Different inputs should produce different IDs")
		})
	}
}

func TestGenerateAddressID_CaseInsensitive(t *testing.T) {
	// Address case should not affect the ID (addresses are normalized to lowercase)
	lowerAddr := "0xabcdef1234567890abcdef1234567890abcdef12"
	upperAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
	grantID := "grant-123"

	idLower := generateAddressID(lowerAddr, grantID)
	idUpper := generateAddressID(upperAddr, grantID)

	assert.Equal(t, idLower, idUpper, "Address IDs should be case-insensitive")
}

func TestGenerateAddressID_NoAddressLeakage(t *testing.T) {
	// The generated ID should not contain the original address
	address := "0xdeadbeef12345678deadbeef12345678deadbeef"
	grantID := "grant-xyz"

	id := generateAddressID(address, grantID)

	// ID should not contain address parts
	assert.NotContains(t, id, "deadbeef")
	assert.NotContains(t, id, "12345678")
	assert.NotContains(t, id, "0x")

	// ID should be hex encoded (16 chars from 8 bytes)
	assert.Len(t, id, 16, "Address ID should be 16 hex characters")
}

func TestGenerateAddressID_Format(t *testing.T) {
	id := generateAddressID("0x1234567890abcdef1234567890abcdef12345678", "grant-123")

	// Should be valid hex
	for _, c := range id {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"ID should only contain valid hex characters")
	}
}

// ============================================================================
// Test: generatePseudonym() - Pseudonym Generation
// ============================================================================

func TestGeneratePseudonym_Consistency(t *testing.T) {
	address := "0x1234567890abcdef1234567890abcdef12345678"

	p1 := generatePseudonym(address)
	p2 := generatePseudonym(address)

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
			result := generatePseudonym(tt.address)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGeneratePseudonym_NoAddressLeakage(t *testing.T) {
	address := "0xdeadbeef12345678deadbeef12345678deadbeef"
	pseudonym := generatePseudonym(address)

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

	p1 := generatePseudonym(addr1)
	p2 := generatePseudonym(addr2)
	p3 := generatePseudonym(addr3)

	assert.NotEqual(t, p1, p2)
	assert.NotEqual(t, p1, p3)
	assert.NotEqual(t, p2, p3)
}

func TestGeneratePseudonym_ShortAddress(t *testing.T) {
	// Edge case: address too short
	shortAddr := "0x12"
	result := generatePseudonym(shortAddr)
	assert.Equal(t, "Address-Unknown", result)

	// Very short
	veryShort := "0x"
	result2 := generatePseudonym(veryShort)
	assert.Equal(t, "Address-Unknown", result2)
}

func TestGeneratePseudonym_CaseInsensitive(t *testing.T) {
	lower := "0xabcd567890abcdef1234567890abcdef12345678"
	upper := "0xABCD567890ABCDEF1234567890ABCDEF12345678"

	pLower := generatePseudonym(lower)
	pUpper := generatePseudonym(upper)

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
	addressID := generateAddressID(testTargetAddress, grantID)

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

	addressID := generateAddressID(testTargetAddress, grantID)

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

	addressID := generateAddressID(testTargetAddress, grantID)

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

	addressID := generateAddressID(testTargetAddress, grantID)

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
	sensitiveAddress := "0xsensitive12345678901234567890123456789012"
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
	assert.NotContains(t, body, "sensitive12345", "SECURITY VIOLATION: Real address parts leaked")
}

func TestSecurity_RedactedDoesNotLeakRealAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Create viewer user
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	// Create target user and link address with unique identifier
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	sensitiveAddress := "0xsecret999999999999999999999999999999999999"
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
	assert.NotContains(t, body, "secret9999", "SECURITY VIOLATION: Real address parts leaked")
	assert.Contains(t, body, "[REDACTED]", "Should show redacted placeholder")
}

// ============================================================================
// Test: Edge Cases
// ============================================================================

func TestEdgeCase_EmptyDID(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupExplorerRouter(srv)

	// Query with empty DID should be rejected
	req := httptest.NewRequest("GET", "/api/v1/explorer/viewable-addresses?did=", nil)
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
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	addr1 := "0xaddr111111111111111111111111111111111111"
	addr2 := "0xaddr222222222222222222222222222222222222"
	addr3 := "0xaddr333333333333333333333333333333333333"
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
