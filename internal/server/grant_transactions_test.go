package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGrantTransactionsRouter creates a gin router with the grant transactions and resolve endpoints.
func setupGrantTransactionsRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/grant/:grant_id/resolve/:address_id", srv.resolveAddressID)
	explorerGroup.GET("/grant/:grant_id/:address_id/transactions", srv.getGrantTransactions)
	return router
}

// testExternalPseudonym replicates generateExternalPseudonym for test assertions.
func testExternalPseudonym(address, grantID string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(address)))
	h.Write([]byte(":"))
	h.Write([]byte(grantID))
	sum := h.Sum(nil)
	return fmt.Sprintf("External-%X", sum[:2])
}

func TestGrantTransactions_FullDisclosure(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	// Create target user and link address
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create full disclosure grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	// Seed transactions: target sends to external, external sends to target
	externalAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_out_1", testTargetAddress, externalAddr)
	block2 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block2, "0xtx_in_1", externalAddr, testTargetAddress)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, "full", resp.DisclosureLevel)
	assert.Len(t, resp.Transactions, 2)

	// Full disclosure includes tx hash, real addresses, and real values
	for _, tx := range resp.Transactions {
		assert.NotNil(t, tx.TxHash, "full disclosure should include tx hash")
		assert.NotEqual(t, "hidden", tx.Value, "full disclosure should include real value")

		// Addresses should be real
		assert.False(t, strings.HasPrefix(tx.From, "Address-"),
			"full disclosure should use real addresses, got %s", tx.From)
		assert.False(t, strings.HasPrefix(tx.From, "External-"),
			"full disclosure should use real addresses, got %s", tx.From)
	}

	// Check directions
	var outCount, inCount int
	for _, tx := range resp.Transactions {
		switch tx.Direction {
		case "out":
			outCount++
			assert.Equal(t, testTargetAddress, tx.From)
		case "in":
			inCount++
			assert.Equal(t, testTargetAddress, tx.To)
		}
	}
	assert.Equal(t, 1, outCount, "should have 1 outgoing tx")
	assert.Equal(t, 1, inCount, "should have 1 incoming tx")
}

func TestGrantTransactions_PseudonymousDisclosure(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	externalAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_pseudo_out", testTargetAddress, externalAddr)
	block2 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block2, "0xtx_pseudo_in", externalAddr, testTargetAddress)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, "pseudonymous", resp.DisclosureLevel)
	assert.Len(t, resp.Transactions, 2)

	disclosedPseudonym := explorer.GeneratePseudonym(testTargetAddress, nil)
	expectedExternalPseudo := testExternalPseudonym(externalAddr, grantID)

	// SECURITY: Response body should NOT contain any real addresses
	body := w.Body.String()
	assert.NotContains(t, body, testTargetAddress,
		"SECURITY VIOLATION: real disclosed address leaked in pseudonymous mode")
	assert.NotContains(t, body, externalAddr,
		"SECURITY VIOLATION: real external address leaked in pseudonymous mode")

	for _, tx := range resp.Transactions {
		// No tx hash for pseudonymous
		assert.Nil(t, tx.TxHash, "pseudonymous should NOT include tx hash")

		// Value should be hidden
		assert.Equal(t, "hidden", tx.Value, "pseudonymous should hide value")

		// Addresses should be pseudonyms
		switch tx.Direction {
		case "out":
			assert.Equal(t, disclosedPseudonym, tx.From)
			assert.Equal(t, expectedExternalPseudo, tx.To)
		case "in":
			assert.Equal(t, expectedExternalPseudo, tx.From)
			assert.Equal(t, disclosedPseudonym, tx.To)
		}
	}

	// Check address labels
	assert.Equal(t, "disclosed", resp.AddressLabels[disclosedPseudonym])
	assert.Equal(t, "external", resp.AddressLabels[expectedExternalPseudo])
}

func TestGrantTransactions_PseudonymousDirection_Self(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	// Self-transaction: target sends to self
	block := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block, "0xtx_self", testTargetAddress, testTargetAddress)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	require.Len(t, resp.Transactions, 1)
	assert.Equal(t, "self", resp.Transactions[0].Direction)
}

func TestGrantTransactions_RedactedDisclosure(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureRedacted, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	externalA := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	externalB := "0xcccccccccccccccccccccccccccccccccccccccc"
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_redacted_out_a", testTargetAddress, externalA)
	block2 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block2, "0xtx_redacted_in_a", externalA, testTargetAddress)
	block3 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block3, "0xtx_redacted_out_b", testTargetAddress, externalB)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, "redacted", resp.DisclosureLevel)
	require.Len(t, resp.Transactions, 3, "redacted should return all txs (proof of activity)")

	body := w.Body.String()
	assert.NotContains(t, body, testTargetAddress, "real disclosed address leaked in redacted mode")
	assert.NotContains(t, body, externalA, "real external address leaked in redacted mode")
	assert.NotContains(t, body, externalB, "real external address leaked in redacted mode")
	assert.NotContains(t, body, "0xtx_redacted", "tx hash leaked in redacted mode")

	for _, tx := range resp.Transactions {
		assert.Nil(t, tx.TxHash, "redacted must NOT include tx hash")
		assert.Equal(t, "hidden", tx.Value, "redacted must hide value")
		assert.Equal(t, "[PRIVATE]", tx.From, "redacted from must be uniform [PRIVATE]")
		assert.Equal(t, "[PRIVATE]", tx.To, "redacted to must be uniform [PRIVATE]")
		assert.NotEmpty(t, tx.Direction, "direction (in/out/self) is preserved for activity proof")
	}

	// Linkability check: the two txs involving externalA must be indistinguishable
	// from the third tx (externalB) on the counterparty side — no per-address stable
	// pseudonym is emitted.
	assert.Empty(t, resp.AddressLabels, "redacted must not emit address labels")
}

func TestGrantTransactions_ExpiredGrant(t *testing.T) {
	srv, database, _ := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Create expired grant
	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(-1*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID) // RD-1164 #10: grantee must be authenticated to see grant state
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "expired")
}

func TestGrantTransactions_RevokedGrant(t *testing.T) {
	srv, database, _ := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)
	ctx := context.Background()

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	// Revoke the grant
	_, err := database.Conn().ExecContext(ctx,
		"UPDATE disclosure_grants SET revoked_at = NOW(), revoked_reason = 'test' WHERE id = $1",
		grantID)
	require.NoError(t, err)

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID) // RD-1164 #10: grantee must be authenticated to see grant state
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "revoked")
}

func TestGrantTransactions_InvalidGrant(t *testing.T) {
	srv, _, _ := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/nonexistent-grant/some-address-id/transactions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGrantTransactions_InvalidAddressID(t *testing.T) {
	srv, database, _ := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/wrong-address-id/transactions", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "address not found")
}

func TestGrantTransactions_Pagination(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	// Seed 5 transactions
	externalAddr := "0xcccccccccccccccccccccccccccccccccccccccc"
	for i := 0; i < 5; i++ {
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block,
			fmt.Sprintf("0xtx_page_%d", i), testTargetAddress, externalAddr)
	}

	// Request with limit=2
	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions?limit=2", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Len(t, resp.Transactions, 2, "should return exactly limit transactions")
	assert.True(t, resp.HasMore, "should indicate more transactions available")
}

// TestResolveAddressID_PseudonymousDoesNotLeakRealAddress verifies the privacy fix
// in resolveAddressID: pseudonymous grants must NOT return real_address.
func TestResolveAddressID_PseudonymousDoesNotLeakRealAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantTransactionsRouter(srv)

	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp ResolveAddressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// SECURITY: real_address must NOT be present for pseudonymous grants
	assert.Nil(t, resp.RealAddress,
		"SECURITY VIOLATION: real address leaked in pseudonymous resolve response")

	// The raw JSON should not contain the real address at all
	body := w.Body.String()
	assert.NotContains(t, body, testTargetAddress,
		"SECURITY VIOLATION: real address found in response body")

	assert.Equal(t, "pseudonymous", resp.DisclosureLevel)
	assert.NotEmpty(t, resp.Pseudonym)
}

// TestResolveAddressID_FullReturnsRealAddress verifies full disclosure still works.
func TestResolveAddressID_FullReturnsRealAddress(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantTransactionsRouter(srv)

	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp ResolveAddressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	require.NotNil(t, resp.RealAddress, "full disclosure should include real address")
	assert.Equal(t, testTargetAddress, *resp.RealAddress)
	assert.Equal(t, "full", resp.DisclosureLevel)
}

// TestResolveAddressID_Anonymous401 is the RD-1164 #10 regression for the
// resolve handler: an unauthenticated caller (no JWT) must be rejected with
// 401 before any address is resolved, even for a valid full-disclosure grant.
// Pre-fix, any caller who knew grant_id + address_id could resolve the real
// address of a full grant they did not hold.
func TestResolveAddressID_Anonymous401(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantTransactionsRouter(srv)

	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	// No bearer token — anonymous.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"anonymous resolve must be rejected 401")
	// The real address must not leak in the error body.
	assert.NotContains(t, w.Body.String(), testTargetAddress)
}

// TestResolveAddressID_WrongViewer404 is the RD-1164 #10 regression: a viewer
// authenticated as someone OTHER than the grant's requester must get a uniform
// 404 (not 403, not 200) so grant existence is not leaked to non-holders.
func TestResolveAddressID_WrongViewer404(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantTransactionsRouter(srv)

	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	// Authenticate as a stranger who does not hold the grant.
	strangerDID := "did:test:resolve_stranger"
	createTestUserForExplorer(t, database, strangerDID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID, nil)
	addBearerToken(t, req, srv, strangerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code,
		"non-holder must get uniform 404, not 403/200, to prevent grant enumeration")
	assert.NotContains(t, w.Body.String(), testTargetAddress)
}

// TestGrantTransactions_Anonymous401 is the RD-1164 #10 regression for the
// grant-transactions handler: an unauthenticated caller must be rejected 401
// before any transaction is disclosed.
func TestGrantTransactions_Anonymous401(t *testing.T) {
	srv, database, _ := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	// No bearer token — anonymous.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"anonymous grant-transactions request must be rejected 401")
}

// TestGrantTransactions_WrongViewer404 is the RD-1164 #10 regression: a viewer
// who is not the grant's requester must get a uniform 404 from the
// grant-transactions handler.
func TestGrantTransactions_WrongViewer404(t *testing.T) {
	srv, database, _ := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createDisclosureGrantWithLevel(t, database, testViewerDID, targetUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	strangerDID := "did:test:txs_stranger"
	createTestUserForExplorer(t, database, strangerDID)

	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions", nil)
	addBearerToken(t, req, srv, strangerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code,
		"non-holder must get uniform 404 from grant-transactions")
}
