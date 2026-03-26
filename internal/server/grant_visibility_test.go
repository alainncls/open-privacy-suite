package server

import (
	"bytes"
	"encoding/json"
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

// setupGrantVisibilityRouter creates a gin router with check-addresses, grant transactions,
// and explorer transactions endpoints for the grant visibility test matrix.
func setupGrantVisibilityRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.POST("/check-addresses", srv.batchCheckAddresses)
	explorerGroup.GET("/grant/:grant_id/:address_id/transactions", srv.getGrantTransactions)
	explorerGroup.GET("/transactions", srv.getExplorerTransactions)
	return router
}

// TestGrantVisibility is the comprehensive test suite covering the interaction between
// disclosure grants, participant override, and the check-addresses API.
func TestGrantVisibility(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantVisibilityRouter(srv)

	// --- Actors ---
	const (
		aliceDID = "did:a:alice"
		daveDID  = "did:d:dave"
		bobDID   = "did:b:bob"

		addrAlice = "0xaaaa000000000000000000000000000000001001"
		addrDave  = "0xdddd000000000000000000000000000000001002"
		addrBob   = "0xbbbb000000000000000000000000000000001003"
	)

	// Create users + link addresses
	createTestUserForExplorer(t, database, aliceDID)
	linkEthAddressToUser(t, database, aliceDID, addrAlice)

	daveUserID := createTestUserForExplorer(t, database, daveDID)
	linkEthAddressToUser(t, database, daveDID, addrDave)

	createTestUserForExplorer(t, database, bobDID)
	linkEthAddressToUser(t, database, bobDID, addrBob)

	// Seed a transaction: Dave → Alice (ETH transfer)
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_dave_to_alice", addrDave, addrAlice)

	// Alice gets a pseudonymous grant on Dave
	pseudoGrantID := createDisclosureGrantWithLevel(t, database, aliceDID, daveUserID,
		disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

	// ========================================================================
	// Test Group 1: check-addresses API (GetBatchVisibilityDetailed)
	// ========================================================================

	t.Run("Group1_CheckAddresses", func(t *testing.T) {
		t.Run("DaveAddr_AsAlice_HiddenNoGrantLeak", func(t *testing.T) {
			body := BatchCheckAddressesRequest{Addresses: []string{addrDave}}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp BatchCheckAddressesResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			vis := resp.Results[addrDave]
			// G16: oracle masking — non-visible masked as public
			// Alice has a pseudonymous grant, but check-addresses must NOT reveal grant existence.
			// The address appears public to prevent address enumeration.
			assert.True(t, vis.Visible, "grant target should appear public in check-addresses (G16 oracle masking)")
			assert.Equal(t, VisibilityFull, vis.Level)
			assert.Equal(t, ReasonPublicAddress, vis.Reason, "reason must be public_address, not disclosure_grant")

			// Grant metadata must NOT be present — check-addresses must not leak grant existence
			assert.Nil(t, vis.GrantID, "grant_id must NOT be returned in check-addresses")
			assert.Nil(t, vis.Pseudonym, "pseudonym must NOT be returned in check-addresses")
		})

		t.Run("DaveAddr_AsBob_HiddenNoMetadata", func(t *testing.T) {
			body := BatchCheckAddressesRequest{Addresses: []string{addrDave}}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			addBearerToken(t, req, srv, bobDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp BatchCheckAddressesResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			vis := resp.Results[addrDave]
			// G16: oracle masking — non-visible masked as public
			assert.True(t, vis.Visible)
			assert.Equal(t, VisibilityFull, vis.Level)
			assert.Equal(t, ReasonPublicAddress, vis.Reason)
			// Bob has no grant — no metadata
			assert.Nil(t, vis.GrantID, "outsider should not see grant_id")
			assert.Nil(t, vis.Pseudonym, "outsider should not see pseudonym")
		})

		t.Run("DaveAddr_AsDave_OwnAddress", func(t *testing.T) {
			body := BatchCheckAddressesRequest{Addresses: []string{addrDave}}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			addBearerToken(t, req, srv, daveDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp BatchCheckAddressesResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			vis := resp.Results[addrDave]
			assert.True(t, vis.Visible)
			assert.Equal(t, VisibilityFull, vis.Level)
			assert.Equal(t, ReasonOwnAddress, vis.Reason)
		})

		t.Run("AliceAddr_AsAlice_OwnAddress", func(t *testing.T) {
			body := BatchCheckAddressesRequest{Addresses: []string{addrAlice}}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp BatchCheckAddressesResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			vis := resp.Results[addrAlice]
			assert.True(t, vis.Visible)
			assert.Equal(t, VisibilityFull, vis.Level)
			assert.Equal(t, ReasonOwnAddress, vis.Reason)
		})

		t.Run("AliceAddr_AsBob_Hidden", func(t *testing.T) {
			body := BatchCheckAddressesRequest{Addresses: []string{addrAlice}}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			addBearerToken(t, req, srv, bobDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp BatchCheckAddressesResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			vis := resp.Results[addrAlice]
			// G16: oracle masking — non-visible masked as public
			assert.True(t, vis.Visible)
			assert.Equal(t, VisibilityFull, vis.Level)
			assert.Equal(t, ReasonPublicAddress, vis.Reason)
		})
	})

	// ========================================================================
	// Test Group 2: Grant transactions endpoint
	// ========================================================================

	t.Run("Group2_GrantTransactions", func(t *testing.T) {
		// Seed a transaction from Dave to an unrelated external address (non-user)
		externalAddr := "0xeeee000000000000000000000000000000001099"
		block2 := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block2, "0xtx_dave_to_ext", addrDave, externalAddr)

		// Seed a transaction from Alice to Dave (so Alice is a participant counterparty)
		block3 := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block3, "0xtx_alice_to_dave", addrAlice, addrDave)

		addressID := explorer.GenerateAddressID(addrDave, pseudoGrantID)
		disclosedPseudonym := explorer.GeneratePseudonym(addrDave)

		t.Run("Pseudonymous_ViewerOwnAddrShowsAsYou", func(t *testing.T) {
			// Alice views Dave's grant transactions. The tx from Alice → Dave should
			// show Alice's address as "Mine" when Alice is authenticated.
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+pseudoGrantID+"/"+addressID+"/transactions", nil)
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "pseudonymous", resp.DisclosureLevel)

			// Find the Alice → Dave tx
			var found bool
			for _, tx := range resp.Transactions {
				if tx.Direction == "in" && tx.From == "Mine" {
					found = true
					assert.Equal(t, disclosedPseudonym, tx.To,
						"disclosed address should show as pseudonym")
					break
				}
			}
			assert.True(t, found, "should find a tx where Alice (viewer) appears as 'You'")
			assert.Equal(t, "mine", resp.AddressLabels["Mine"])
		})

		t.Run("Pseudonymous_DisclosedAddrShowsAsPseudonym", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+pseudoGrantID+"/"+addressID+"/transactions", nil)
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "disclosed", resp.AddressLabels[disclosedPseudonym],
				"disclosed pseudonym should be labeled 'disclosed'")

			// The response body must not contain the real address
			body := w.Body.String()
			assert.NotContains(t, body, addrDave,
				"SECURITY: real address must not leak in pseudonymous mode")
		})

		t.Run("Pseudonymous_ExternalAddrShowsAsExternalXXXX", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+pseudoGrantID+"/"+addressID+"/transactions", nil)
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			expectedExternalPseudo := testExternalPseudonym(externalAddr, pseudoGrantID)

			// Find the Dave → external tx
			var found bool
			for _, tx := range resp.Transactions {
				if tx.To == expectedExternalPseudo {
					found = true
					assert.Equal(t, disclosedPseudonym, tx.From,
						"from should be disclosed pseudonym")
					break
				}
			}
			assert.True(t, found, "should find a tx with External-XXXX pseudonym for external address")
			assert.Equal(t, "external", resp.AddressLabels[expectedExternalPseudo])

			// Real external address must not appear
			body := w.Body.String()
			assert.NotContains(t, body, externalAddr,
				"SECURITY: real external address must not leak")
		})

		t.Run("FullGrant_RealAddressesShown", func(t *testing.T) {
			fullGrantID := createDisclosureGrantWithLevel(t, database, aliceDID, daveUserID,
				disclosure.DisclosureFull, time.Now().Add(24*time.Hour))
			fullAddressID := explorer.GenerateAddressID(addrDave, fullGrantID)

			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+fullGrantID+"/"+fullAddressID+"/transactions", nil)
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "full", resp.DisclosureLevel)
			require.NotEmpty(t, resp.Transactions, "full grant should return transactions")

			for _, tx := range resp.Transactions {
				assert.NotNil(t, tx.TxHash, "full disclosure should include tx hash")
				assert.NotEqual(t, "hidden", tx.Value, "full disclosure should include real value")
				// Addresses should be real, not pseudonyms
				assert.False(t, strings.HasPrefix(tx.From, "Address-"),
					"full disclosure should use real addresses, got %s", tx.From)
				assert.False(t, strings.HasPrefix(tx.From, "External-"),
					"full disclosure should use real addresses, got %s", tx.From)
			}
		})

		t.Run("RedactedGrant_EmptyTransactions", func(t *testing.T) {
			redactedGrantID := createDisclosureGrantWithLevel(t, database, aliceDID, daveUserID,
				disclosure.DisclosureRedacted, time.Now().Add(24*time.Hour))
			redactedAddressID := explorer.GenerateAddressID(addrDave, redactedGrantID)

			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+redactedGrantID+"/"+redactedAddressID+"/transactions", nil)
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "redacted", resp.DisclosureLevel)
			assert.Empty(t, resp.Transactions, "redacted grant should return empty transactions")
		})
	})

	// ========================================================================
	// Test Group 3: Regular explorer does NOT leak grants
	// ========================================================================

	t.Run("Group3_RegularExplorerNoLeak", func(t *testing.T) {
		t.Run("Alice_ParticipantOverride_SeesRealAddresses", func(t *testing.T) {
			// Alice is the recipient of the Dave → Alice tx. Participant override
			// should make the tx visible and show the real counterparty address.
			req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			txs := parseTransactionsResponse(t, w.Body.Bytes())

			// Alice should see transactions where she is a participant
			var daveToAliceTx *explorer.Transaction
			for i, tx := range txs {
				if tx.HasRecipient() && strings.EqualFold(*tx.To, addrAlice) &&
					strings.EqualFold(tx.From, addrDave) {
					daveToAliceTx = &txs[i]
					break
				}
			}
			require.NotNil(t, daveToAliceTx, "Alice (participant) should see Dave → Alice tx")
			// Participant override shows real addresses
			assert.Equal(t, addrDave, strings.ToLower(daveToAliceTx.From),
				"participant override should reveal real counterparty address")
			require.NotNil(t, daveToAliceTx.To)
			assert.Equal(t, addrAlice, strings.ToLower(*daveToAliceTx.To))
		})

		t.Run("Bob_NoGrantNotParticipant_CannotSeeTx", func(t *testing.T) {
			// Bob has no grant and is not a participant in Dave → Alice tx.
			// Both Dave and Alice are hidden EOAs from Bob's perspective — tx must be dropped.
			req := httptest.NewRequest("GET", "/api/v1/explorer/transactions", nil)
			addBearerToken(t, req, srv, bobDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			txs := parseTransactionsResponse(t, w.Body.Bytes())

			for _, tx := range txs {
				if tx.HasRecipient() && strings.EqualFold(*tx.To, addrAlice) &&
					strings.EqualFold(tx.From, addrDave) {
					t.Fatal("Bob must NOT see Dave → Alice tx (both sides hidden, not a participant)")
				}
			}
		})

		t.Run("CheckAddresses_GrantHolder_ReasonIsPublicAddress", func(t *testing.T) {
			// G16: oracle masking — non-visible masked as public
			// Even though Alice has a grant on Dave, the check-addresses API should
			// report reason=public_address (NOT disclosure_grant) for the address visibility.
			body := BatchCheckAddressesRequest{Addresses: []string{addrDave}}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/explorer/check-addresses", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			addBearerToken(t, req, srv, aliceDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp BatchCheckAddressesResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			vis := resp.Results[addrDave]
			assert.Equal(t, ReasonPublicAddress, vis.Reason,
				"grant holder should see reason=public_address in check-addresses, not disclosure_grant")
			assert.True(t, vis.Visible,
				"grant target should appear public in check-addresses (G16 oracle masking)")
		})
	})
}
