package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCountSurfaceRouter wires the address stats badge endpoint alongside the
// three list endpoints whose row counts the badges must match.
func setupCountSurfaceRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	g.GET("/addresses/:address/stats", srv.getExplorerAddressStats)
	g.GET("/addresses/:address/transactions", srv.getExplorerAddressTransactions)
	g.GET("/addresses/:address/transfers", srv.getExplorerAddressTransfers)
	g.GET("/addresses/:address/internal", srv.getExplorerAddressInternal)
	return r
}

// TestExplorerAddressStats_AllCountsVisibilityFiltered_RD1154 is the parity
// guard for the count-surface leak: every address-stats badge (Transactions /
// Token transfers / Internal txns) must equal the number of rows the viewer can
// actually load on the matching list surface — never the raw address_stats
// aggregate. Before RD-1154 only TxCount was filtered; TokenTransferCount and
// InternalTxCount were returned RAW, so a restricted viewer's badge revealed how
// many rows exist that they cannot see.
//
// The invariant asserted for EVERY viewer, on EVERY surface:
//
//	stats.<Count> == len(fully-visible list rows for that viewer)   AND   != raw aggregate (99)
//
// This holds regardless of why a given viewer sees more or fewer rows (admin,
// grant lens, participant, G10 drops) — it pins badge↔list agreement directly.
//
// MUTATION CHECK: revert the TokenTransferCount/InternalTxCount filtering in
// getExplorerAddressStats and the badges fall back to the raw 99, breaking both
// the parity assertion and the "!= 99" assertion.
func TestExplorerAddressStats_AllCountsVisibilityFiltered_RD1154(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	// --- Subject contract, org-owned (visible to org members via the grant). ---
	subject := "0xc0ffee0000000000000000000000000000000001"
	groupID := registerOrgContract(t, database, subject)

	// Admin: is_org_admin of the subject's org + a member of the grant group
	// (is_org_admin alone does not confer contract visibility — see
	// address_stats_visibility_test.go).
	aliceDID := "did:test:alice_counts"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-counts', 'Admins', 0, 'admins-counts', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)
	addUserToGroup(t, database, aliceUserID, groupID)

	// Restricted viewer: sees `subject` via the grant group, but is NOT an admin
	// and is NOT a participant of any of its activity.
	eveDID := "did:test:eve_counts"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID)

	// Hidden foreign counterparties (unregistered ⇒ private by default).
	hiddenA := "0xdead000000000000000000000000000000000001"
	hiddenB := "0xdead000000000000000000000000000000000002"
	hiddenToken := "0xdead000000000000000000000000000000000003"

	blockNum := seedExplorerBlock(t, conn)

	// 3 transactions: subject <-> hidden.
	txHashes := []string{"0xcnt_tx_0", "0xcnt_tx_1", "0xcnt_tx_2"}
	for i, h := range txHashes {
		_, err = conn.ExecContext(ctx,
			`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
			 VALUES ($1, $2, $3, $4, $5, 0, 21000, 1000, 1, '0x')`,
			h, blockNum, i, subject, hiddenA)
		require.NoError(t, err)
	}

	// 2 token transfers where `subject` is a party (parent txs reused, FK-safe).
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, txHashes[0], hiddenToken, subject, hiddenA, blockNum)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 2000, $5)`, txHashes[1], hiddenToken, subject, hiddenB, blockNum)
	require.NoError(t, err)

	// 2 internal txs where `subject` is a party.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 5, 'CALL')`, txHashes[0], blockNum, subject, hiddenA)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 5, 'CALL')`, txHashes[1], blockNum, subject, hiddenB)
	require.NoError(t, err)

	// Inflated RAW aggregate — the value the buggy handler would leak.
	const rawAggregate = 99
	_, err = conn.ExecContext(ctx,
		`INSERT INTO address_stats (address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract)
		 VALUES ($1, $2, $2, $2, 1, 1, true)`, subject, rawAggregate)
	require.NoError(t, err)

	router := setupCountSurfaceRouter(srv)

	getStats := func(t *testing.T, did string) explorer.AddressStats {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+subject+"/stats", nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "stats should be 200 for a viewer who can see the subject")
		var stats explorer.AddressStats
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stats))
		return stats
	}
	// listLen returns the visible row count for a surface. bareArray=true for
	// endpoints that return a raw JSON array; false for {"data":[...]} envelopes.
	listLen := func(t *testing.T, did, suffix string, bareArray bool) int {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+subject+suffix, nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "list %s should be 200", suffix)
		if bareArray {
			var rows []json.RawMessage
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rows))
			return len(rows)
		}
		var env struct {
			Data []json.RawMessage `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		return len(env.Data)
	}

	assertParity := func(t *testing.T, did string) explorer.AddressStats {
		t.Helper()
		stats := getStats(t, did)
		assert.Equal(t, listLen(t, did, "/transactions", true), stats.TxCount,
			"Transactions badge must equal the visible tx-list length")
		assert.Equal(t, listLen(t, did, "/transfers", true), stats.TokenTransferCount,
			"Token transfers badge must equal the visible transfer-list length")
		assert.Equal(t, listLen(t, did, "/internal", false), stats.InternalTxCount,
			"Internal txns badge must equal the visible internal-list length")
		// None of the badges may be the raw aggregate.
		assert.NotEqual(t, rawAggregate, stats.TxCount, "TxCount must not be the raw aggregate")
		assert.NotEqual(t, rawAggregate, stats.TokenTransferCount, "TokenTransferCount must not be the raw aggregate")
		assert.NotEqual(t, rawAggregate, stats.InternalTxCount, "InternalTxCount must not be the raw aggregate")
		return stats
	}

	var adminStats, eveStats explorer.AddressStats
	t.Run("admin badges match admin's visible rows (never raw)", func(t *testing.T) {
		adminStats = assertParity(t, aliceDID)
	})
	t.Run("restricted viewer badges match viewer's visible rows (never raw)", func(t *testing.T) {
		eveStats = assertParity(t, eveDID)
	})
	t.Run("filtering actually diverges per viewer", func(t *testing.T) {
		// The restricted viewer must see strictly fewer token transfers than the
		// admin — proving the transfer badge is filtered per viewer, not shared.
		assert.Less(t, eveStats.TokenTransferCount, adminStats.TokenTransferCount,
			"restricted viewer should see fewer transfers than admin")
	})
}

// TestExplorerInternalTx_ParticipantRevealLabeledCounterparty_RD1155 pins the
// reason-tag fix: when an internal-tx trace address is revealed because the
// viewer is a transfer PARTICIPANT of the parent tx (the RD-1009 union), it must
// be labeled participant_override ("Counterparty"), NOT visible_to_grant
// ("Shared") — nothing was shared with the viewer.
//
// Fixture (RD-1009 coherence shape, non-admin viewer):
//   - eve's org owns a "vault" contract eve sees at Full (eve is NOT admin and
//     NOT the internal frame's from/to).
//   - a foreign private wallet calls a foreign private token contract.
//   - the token's Transfer credits eve's vault ⇒ the RD-1009 union pulls the
//     parent tx into eve's visible set (as a participant, not a share).
//   - the internal call is between the two foreign (Hidden) addresses.
//
// MUTATION CHECK: revert the ParticipantTxHashes plumbing and the revealed
// addresses fall through to ReasonVisibleToGrant → the assertion below fails.
func TestExplorerInternalTx_ParticipantRevealLabeledCounterparty_RD1155(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})

	// eve's org-owned vault contract (the transfer recipient eve sees at Full).
	vault := "0xec00000000000000000000000000000000000001"
	groupID := registerOrgContract(t, database, vault)
	eveDID := "did:test:eve_rd1155"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID) // non-admin member ⇒ sees vault at Full

	// Foreign, Hidden-to-eve parties.
	foreignEOA := "0xdead000000000000000000000000000000000021"
	foreignToken := "0xdead000000000000000000000000000000000022"

	blockNum := seedExplorerBlock(t, conn)
	txHash := "0xrd1155_participant_reveal"
	seedExplorerTransaction(t, conn, blockNum, txHash, foreignEOA, foreignToken)

	// Transfer: foreignToken emits Transfer(from=foreignEOA, to=vault) ⇒ eve is a
	// transfer participant of txHash (RD-1009 union adds it to eve's visible set).
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, txHash, foreignToken, foreignEOA, vault, blockNum)
	require.NoError(t, err)

	// Internal call between the two foreign (Hidden) addresses — the nested frame
	// the viewer is NOT a direct participant of.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 50, 'CALL')`, txHash, blockNum, foreignEOA, foreignToken)
	require.NoError(t, err)

	router := setupCoherenceRouter(srv)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/explorer/transactions/"+txHash+"/internal", nil)
	addBearerToken(t, req, srv, eveDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "internal-tx surface should be 200 for the transfer-participant viewer")

	// The per-tx internal endpoint returns a bare JSON array.
	var itxs []struct {
		From            string            `json:"from"`
		To              *string           `json:"to"`
		AddressMetadata map[string]string `json:"addressMetadata"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &itxs))
	require.NotEmpty(t, itxs,
		"PRE-CONDITION: the internal tx must survive for the participant viewer (RD-1009 union). "+
			"If empty, the union fixture is broken before the label assertion is meaningful.")

	sawParticipantOverride := false
	for _, itx := range itxs {
		require.NotEmpty(t, itx.AddressMetadata,
			"revealed internal tx must carry address metadata reasons")
		for addr, reason := range itx.AddressMetadata {
			assert.NotEqual(t, string(explorer.ReasonVisibleToGrant), reason,
				"address %s revealed via participation must NOT be labeled visible_to_grant (\"Shared\")", addr)
			assert.Equal(t, string(explorer.ReasonParticipantOverride), reason,
				"address %s revealed via the transfer-participant union must be labeled participant_override (\"Counterparty\")", addr)
			if reason == string(explorer.ReasonParticipantOverride) {
				sawParticipantOverride = true
			}
		}
	}
	assert.True(t, sawParticipantOverride,
		"expected at least one participant_override-labeled address in the revealed internal tx")
}
