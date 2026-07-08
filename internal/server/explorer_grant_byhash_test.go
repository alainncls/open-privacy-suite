package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupByHashGrantRouter wires the surfaces exercised in this file:
//   - /transactions/:hash (by-hash, the CTO-reported reproducer)
//   - /transactions       (list — confirms row-survival agrees with by-hash)
//   - /transactions/:hash/transfers / /internal (cross-redactor invariant)
func setupByHashGrantRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/transactions", srv.getExplorerTransactions)
	explorerGroup.GET("/transactions/:hash", srv.getExplorerTransaction)
	explorerGroup.GET("/transactions/:hash/transfers", srv.getExplorerTransactionTransfers)
	explorerGroup.GET("/transactions/:hash/internal", srv.getExplorerTransactionInternal)
	return router
}

// TestExplorerByHash_DisclosureGrant_AllLevelsReturn200 pins the CTO-
// reported bug: a viewer holding a disclosure grant on Bob hits
// GET /transactions/:hash for a tx that Bob participated in with an
// otherwise-private counterparty. Pre-fix, the redactor's G10 / bothHidden
// drop returned an empty slice, the handler returned 404, the BFF returned
// 500, and the FE showed "Transaction Restricted." The matrix in
// /docs/security/privacy-requirements §"Row-survival rules per surface"
// says all three grant levels must keep the row — only the field-level
// rendering differs.
//
// The test drives the by-hash surface for {Full, Pseudonymous, Redacted}
// against the same fixture and asserts:
//   - HTTP 200 (not 404)
//   - granted target renders per its level
//   - counterparty renders per the matrix
//   - GET /transactions list contains the same hash (list/by-hash coherence)
//   - For Full grant, the rbac_audit_log records the regulatory reveal.
func TestExplorerByHash_DisclosureGrant_AllLevelsReturn200(t *testing.T) {
	cases := []struct {
		name              string
		level             disclosure.DisclosureLevel
		wantGrantedRender func(addr string) string
		wantCounterRender func(addr string) string
		wantAuditEntry    bool
	}{
		{
			name:              "FullGrant_CounterpartyRevealed",
			level:             disclosure.DisclosureFull,
			wantGrantedRender: func(a string) string { return a },
			wantCounterRender: func(a string) string { return a },
			wantAuditEntry:    true,
		},
		{
			name:  "PseudonymousGrant_BothLensed",
			level: disclosure.DisclosurePseudonymous,
			// nil key mirrors the test server's config (ExplorerPseudonymKey
			// unset) so the expected pseudonym matches the redactor's output.
			wantGrantedRender: func(a string) string { return explorer.GeneratePseudonym(a, nil) },
			wantCounterRender: func(a string) string { return explorer.GeneratePseudonym(a, nil) },
			wantAuditEntry:    false,
		},
		{
			name:              "RedactedGrant_BothPrivate_ValuePreserved",
			level:             disclosure.DisclosureRedacted,
			wantGrantedRender: func(a string) string { return "[PRIVATE]" },
			wantCounterRender: func(a string) string { return "[PRIVATE]" },
			wantAuditEntry:    false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv, database, conn := setupTestServerForExplorerTransactions(t)
			router := setupByHashGrantRouter(srv)

			// Actors
			viewerDID := "did:test:auditor_" + string(tc.level)
			targetDID := "did:test:bob_" + string(tc.level)
			privateCounterAddr := "0xcccc000000000000000000000000000000000099"

			// Bob's EOA — owned by targetDID. Different addresses per
			// sub-test to avoid the multi-grant MAX-rank merge in
			// getDisclosedAddressesWithLevels rolling Pseudonymous up to
			// Full across runs in the same test binary.
			grantedAddr := fmt.Sprintf("0xbbbb%020s%012s", string(tc.level)[:4], "deadbeef0000")

			// Create viewer (no grant target).
			createTestUserForExplorer(t, database, viewerDID)

			// Create target user with linked EOA.
			targetUserID := createTestUserForExplorer(t, database, targetDID)
			linkEthAddressToUser(t, database, targetDID, grantedAddr)

			// Grant disclosure at the test level. Helper handles
			// scope.disclosure_level — see createDisclosureGrantWithLevel.
			createDisclosureGrantWithLevel(t, database, viewerDID, targetUserID, tc.level,
				time.Now().Add(24*time.Hour))

			// Seed the reproducer tx: Bob → privateCounterAddr.
			block := seedExplorerBlock(t, conn)
			txHash := "0xbyhash_" + string(tc.level)
			seedExplorerTransaction(t, conn, block, txHash, grantedAddr, privateCounterAddr)

			// Pre-existing audit-log row count for the viewer — we'll
			// diff this at the end to confirm the Full-grant reveal
			// emitted exactly one new entry.
			preAuditCount := countDisclosureGrantAuditEntries(t, database, viewerDID)

			// ---- /transactions/:hash (the reproducer surface) ----
			req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/transactions/"+txHash, nil)
			addBearerToken(t, req, srv, viewerDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equalf(t, http.StatusOK, w.Code,
				"Bug A — %s by-hash MUST return 200 (matrix row-survival); got %d body=%s",
				tc.level, w.Code, w.Body.String())

			var got explorer.Transaction
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

			if got.From != tc.wantGrantedRender(grantedAddr) {
				t.Errorf("by-hash From: want %q, got %q", tc.wantGrantedRender(grantedAddr), got.From)
			}
			if got.To == nil || *got.To != tc.wantCounterRender(privateCounterAddr) {
				t.Errorf("by-hash To: want %q, got %v (Bug B counterparty-rendering check)",
					tc.wantCounterRender(privateCounterAddr), got.To)
			}

			// ---- /transactions list — coherence with by-hash ----
			req2 := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/transactions", nil)
			addBearerToken(t, req2, srv, viewerDID)
			w2 := httptest.NewRecorder()
			router.ServeHTTP(w2, req2)
			require.Equal(t, http.StatusOK, w2.Code)

			rows := parseTransactionsResponse(t, w2.Body.Bytes())
			found := false
			for _, r := range rows {
				if r.Hash == txHash {
					found = true
					break
				}
			}
			require.Truef(t, found,
				"list-path COHERENCE — /transactions must contain the hash that by-hash returned (level=%s)",
				tc.level)

			// ---- Audit-log assertion: Full grant must emit a reveal entry.
			postAuditCount := countDisclosureGrantAuditEntries(t, database, viewerDID)
			delta := postAuditCount - preAuditCount

			if tc.wantAuditEntry {
				// The total of audit entries after by-hash + list calls is
				// >= 2 (at least one per call where a Full-grant reveal
				// occurred). We assert AT LEAST 1 to avoid coupling to
				// the exact call count.
				require.GreaterOrEqualf(t, delta, 1,
					"Full-grant counterparty reveal MUST audit-log (regulatory subpoena trail); delta=%d", delta)
			} else {
				assert.Equalf(t, 0, delta,
					"non-Full grants must NOT emit grant-reveal audit entries; delta=%d", delta)
			}
		})
	}
}

// countDisclosureGrantAuditEntries returns the number of rbac_audit_log
// rows with resource_type=disclosure_grant and the given actor. Used to
// diff audit emission across by-hash assertions.
func countDisclosureGrantAuditEntries(t *testing.T, database *db.DB, actorDID string) int {
	t.Helper()
	row := database.Conn().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM rbac_audit_log WHERE resource_type = $1 AND actor_external_id = $2`,
		rbac.ResourceTypeDisclosureGrant, actorDID)
	var n int
	require.NoError(t, row.Scan(&n))
	return n
}
