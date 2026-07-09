package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createScopedGrantRD1167 creates an approved disclosure grant whose Scope
// carries the given addresses/date-range (the shared helper only sets
// disclosure_level).
func createScopedGrantRD1167(t *testing.T, database *db.DB, requesterDID, targetUserID string, scope disclosure.Scope, expiresAt time.Time) string {
	t.Helper()
	ctx := context.Background()
	orgID, _ := ensureDefaultOrgMembership(t, database, requesterDID)
	if scope.DisclosureLevel == "" {
		scope.DisclosureLevel = disclosure.DisclosureFull
	}
	scopeJSON, err := json.Marshal(scope)
	require.NoError(t, err)

	reqID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		 VALUES ($1,$2,$3,$4,$5,'RD-1167 test','approved',NOW())`,
		reqID, requesterDID, targetUserID, orgID, scopeJSON)
	require.NoError(t, err)

	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
		 VALUES ($1,$2,$3,$4,NOW(),$5)`,
		grantID, reqID, "test-hash-"+grantID, scopeJSON, expiresAt)
	require.NoError(t, err)
	return grantID
}

// seedBlockWithTS seeds a block with an explicit timestamp (the shared
// seedExplorerBlock hardcodes time.Now()).
func seedBlockWithTS(t *testing.T, conn *sql.DB, ts int64) int64 {
	t.Helper()
	num := atomic.AddInt64(&explorerBlockCounter, 1)
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		 VALUES ($1,$2,$3,$4,21000,30000000,1)`,
		num, fmt.Sprintf("0xblock%d", num), fmt.Sprintf("0xparent%d", num-1), ts)
	require.NoError(t, err)
	return num
}

func grantTxResponse(t *testing.T, router http.Handler, srv *Server, grantID, addressID, query string) GrantTransactionsResponse {
	t.Helper()
	req := httptest.NewRequest("GET",
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions"+query, nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp
}

// RD-1167: with an address-scoped grant whose newest page is entirely
// out-of-scope, the in-scope txs further back must still be reachable. The old
// code filtered only the first limit+1 fetched rows, so those in-scope txs were
// invisible and has_more was falsely false.
func TestGrantTransactions_ScopeReachesDeepInScopeTxs_RD1167(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	scopedCounterparty := "0xdddddddddddddddddddddddddddddddddddddddd"
	otherCounterparty := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	// Grant scoped to ONE counterparty: only txs target<->scopedCounterparty
	// are in scope.
	grantID := createScopedGrantRD1167(t, database, testViewerDID, targetUserID,
		disclosure.Scope{Addresses: []string{scopedCounterparty}}, time.Now().Add(24*time.Hour))
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	// The block counter is monotonic (higher block# = newer, returned first).
	// Seed the 3 in-scope txs FIRST so they sit at the OLDEST blocks — behind
	// the newest page. Old code fetched only the newest limit+1 (26) and filtered
	// those, so these 3 were unreachable and has_more was falsely false.
	for i := 0; i < 3; i++ {
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, fmt.Sprintf("0xin_%d", i), testTargetAddress, scopedCounterparty)
	}
	// Newest 30 txs are OUT of scope (target<->otherCounterparty).
	for i := 0; i < 30; i++ {
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, fmt.Sprintf("0xout_%d", i), testTargetAddress, otherCounterparty)
	}

	resp := grantTxResponse(t, router, srv, grantID, addressID, "")
	assert.Len(t, resp.Transactions, 3, "the 3 in-scope txs behind the out-of-scope page must be reachable")
	// The returned txs must be exactly the in-scope ones (0xin_*), not any of the
	// newer out-of-scope 0xout_* txs.
	gotHashes := map[string]bool{}
	for _, tx := range resp.Transactions {
		require.NotNil(t, tx.TxHash, "full-disclosure grant should expose tx_hash")
		gotHashes[*tx.TxHash] = true
	}
	for i := 0; i < 3; i++ {
		assert.True(t, gotHashes[fmt.Sprintf("0xin_%d", i)], "in-scope tx 0xin_%d must be returned", i)
	}
	assert.False(t, resp.HasMore, "no more in-scope txs beyond the 3")
}

// RD-1167: has_more is computed from the in-scope accumulation across pages, not
// a pre-filter page. 30 in-scope txs, limit 25 → page1 returns 25 has_more=true;
// page2 returns 5 has_more=false.
func TestGrantTransactions_HasMoreAcrossPages_RD1167(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	grantID := createScopedGrantRD1167(t, database, testViewerDID, targetUserID,
		disclosure.Scope{}, time.Now().Add(24*time.Hour)) // no scope restriction
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	ext := "0xcccccccccccccccccccccccccccccccccccccccc"
	for i := 0; i < 30; i++ {
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, fmt.Sprintf("0xhm_%d", i), testTargetAddress, ext)
	}

	page1 := grantTxResponse(t, router, srv, grantID, addressID, "?limit=25")
	assert.Len(t, page1.Transactions, 25, "page 1 returns exactly limit")
	assert.True(t, page1.HasMore, "page 1 must report has_more with 30 in-scope txs")

	// Page 2: before = the lowest block number on page 1.
	var p1min uint64 = 1<<63 - 1
	for _, tx := range page1.Transactions {
		if tx.BlockNumber < p1min {
			p1min = tx.BlockNumber
		}
	}
	page2 := grantTxResponse(t, router, srv, grantID, addressID, "?limit=25&before="+strconv.FormatUint(p1min, 10))
	assert.Len(t, page2.Transactions, 5, "page 2 returns the remaining 5")
	assert.False(t, page2.HasMore, "page 2 is the last page")
}

// RD-1167: date-scoped grant — txs whose block timestamp is outside the range
// are excluded even if they are the newest; in-range txs further back are
// reachable.
func TestGrantTransactions_DateScopeReachesInRange_RD1167(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantTransactionsRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)

	// Scope: a 2-day window in the past.
	rangeStart := time.Now().Add(-72 * time.Hour)
	rangeEnd := time.Now().Add(-24 * time.Hour)
	grantID := createScopedGrantRD1167(t, database, testViewerDID, targetUserID,
		disclosure.Scope{DateRange: &disclosure.DateRange{Start: rangeStart, End: rangeEnd}},
		time.Now().Add(24*time.Hour))
	addressID := explorer.GenerateAddressID(testTargetAddress, grantID)

	ext := "0xffffffffffffffffffffffffffffffffffffffff"
	// Block numbers are assigned monotonically at seed time and the query orders
	// by block_number DESC, so seed the 4 in-range (older-timestamp) txs FIRST —
	// they get the LOWEST block numbers and sit BEHIND the newest page. Without
	// the fix, the newest limit+1 fetch would be all out-of-range and the 4
	// in-range txs (deeper) would be unreachable.
	inRangeTs := rangeStart.Add(12 * time.Hour).Unix()
	for i := 0; i < 4; i++ {
		block := seedBlockWithTS(t, conn, inRangeTs)
		seedExplorerTransaction(t, conn, block, fmt.Sprintf("0xin_%d", i), testTargetAddress, ext)
	}
	// Newest 30 blocks: timestamped NOW (after rangeEnd → out of scope), seeded
	// AFTER so they get the HIGHEST block numbers and form the newest page.
	for i := 0; i < 30; i++ {
		block := seedBlockWithTS(t, conn, time.Now().Unix())
		seedExplorerTransaction(t, conn, block, fmt.Sprintf("0xnow_%d", i), testTargetAddress, ext)
	}

	resp := grantTxResponse(t, router, srv, grantID, addressID, "")
	assert.Len(t, resp.Transactions, 4, "only the 4 in-range txs are disclosed, and they are reachable behind the out-of-range page")
	// Confirm they are the in-range ones, not any out-of-range 0xnow_* tx.
	for _, tx := range resp.Transactions {
		require.NotNil(t, tx.TxHash)
		assert.Contains(t, *tx.TxHash, "0xin_", "returned tx must be an in-range one")
	}
	assert.False(t, resp.HasMore, "no more in-range txs beyond the 4")
}
