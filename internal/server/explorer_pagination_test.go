package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsePaginatedResponse unmarshals a paginated transactions response into
// total count and a slice of transactions.
func parsePaginatedResponse(t *testing.T, body []byte) (int64, []explorer.Transaction) {
	t.Helper()
	var resp struct {
		Data  []explorer.Transaction `json:"data"`
		Total int64                  `json:"total"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Total, resp.Data
}

// setupPaginatedTransactionsRouter creates a gin router with the paginated
// transactions endpoint and OptionalJWTAuthMiddleware.
func setupPaginatedTransactionsRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/transactions/paginated", srv.getExplorerTransactionsPaginated)
	return router
}

func TestExplorerTransactionsPaginated_VisibilityFiltering(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// --- RBAC setup ---

	// Create org with a contract registered to it.
	privateAddr := "0xaaaa000000000000000000000000000000000001"
	groupID := registerOrgContract(t, database, privateAddr)

	// Create user alice as an ADMIN of the org's group so she can see the contract's txs.
	aliceDID := "did:test:alice"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	
	adminGroupID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-pag', 'Admins', 0, 'admins-pag', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)

	// Create user bob and link an EOA to him.
	bobDID := "did:test:bob"
	_ = createTestUserForExplorer(t, database, bobDID)
	privateUserAddr := "0xcccc000000000000000000000000000000000001"
	err = database.SystemLinkEthAddress(ctx, bobDID, privateUserAddr)
	require.NoError(t, err)

	// --- Explorer data setup ---

	publicFrom := "0xbbbb000000000000000000000000000000000001"
	publicTo := "0xbbbb000000000000000000000000000000000002"

	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (1, '0xblockhash_pag1', '0x0', 1000, 21000, 30000000, 7, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	// tx1: from private contract, contract creation (to = NULL) — hidden from anonymous
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag1', 1, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)

	// tx2: from private contract, contract creation (to = NULL) — hidden from anonymous
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag2', 1, 1, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)

	// tx3: public-to-public — visible to everyone
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag3', 1, 2, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, publicTo)
	require.NoError(t, err)

	// tx4: public-to-public — visible to everyone
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag4', 1, 3, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, publicTo)
	require.NoError(t, err)

	// tx5: public-to-public — visible to everyone
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag5', 1, 4, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, publicTo)
	require.NoError(t, err)

	// tx6: from private user EOA, contract creation — hidden from anonymous and non-granted users (like alice)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag6', 1, 5, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateUserAddr)
	require.NoError(t, err)

	// tx7: from private user EOA, contract creation — hidden from anonymous and non-granted users (like alice)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_pag7', 1, 6, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateUserAddr)
	require.NoError(t, err)

	// --- Test cases ---

	t.Run("anonymous viewer gets filtered total and correct page size", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(3), total, "anonymous viewer should see only 3 public transactions")
		assert.Len(t, txs, 3, "page 1 should contain all 3 visible transactions")

		// None of the returned transactions should involve the private contract or user address.
		for _, tx := range txs {
			assert.NotEqual(t, privateAddr, strings.ToLower(tx.From), "private contract address must not appear")
			assert.NotEqual(t, privateUserAddr, strings.ToLower(tx.From), "private user address must not appear")
		}
	})

	t.Run("authenticated org member sees public and org transactions, but not other private user txs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, aliceDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(5), total, "alice should see 3 public + 2 org txs = 5")
		assert.Len(t, txs, 5, "page 1 should contain all 5 transactions for org member")

		for _, tx := range txs {
			assert.NotEqual(t, privateUserAddr, strings.ToLower(tx.From), "private user address must not appear for alice")
		}
	})

	t.Run("authenticated user sees public and own transactions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(5), total, "bob should see 3 public + 2 own txs = 5")
		assert.Len(t, txs, 5, "page 1 should contain all 5 transactions for bob")

		for _, tx := range txs {
			assert.NotEqual(t, privateAddr, strings.ToLower(tx.From), "private org address must not appear for bob")
		}
	})

	t.Run("non-admin grant holder sees public and org transactions", func(t *testing.T) {
		// Eve is a member of a NON-admin group with a 'read' contract_grant on the contract.
		// Any grant holder now gets VisibilityFull on the granted contract, so Eve should
		// see org contract transactions (same as Alice the admin).
		eveDID := "did:test:eve"
		eveUserID := createTestUserForExplorer(t, database, eveDID)

		// Create a non-admin group in the same org as the private contract.
		readGroupID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'readers-pag', 'Readers', 0, 'readers-pag', false)",
			readGroupID, groupID)
		require.NoError(t, err)

		// Grant only 'read' claim on the contract to this group.
		var contractID string
		err = conn.QueryRowContext(ctx,
			"SELECT id FROM contracts WHERE LOWER(address) = $1", privateAddr).Scan(&contractID)
		require.NoError(t, err)

		_, err = conn.ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{read}')",
			uuid.New().String(), contractID, readGroupID)
		require.NoError(t, err)

		addUserToGroup(t, database, eveUserID, readGroupID)

		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, eveDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(5), total, "grant holder (Eve) should see 3 public + 2 org contract txs = 5")
		assert.Len(t, txs, 5, "page should contain all 5 visible transactions for grant holder")

		for _, tx := range txs {
			assert.NotEqual(t, privateUserAddr, strings.ToLower(tx.From), "private user address must not appear for Eve")
		}
	})

	t.Run("pagination page 2 is empty when all visible txs fit in page 1", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=2&pageSize=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(3), total, "total should still reflect filtered count")
		assert.Len(t, txs, 0, "page 2 should be empty when all visible txs fit in page 1")
	})
}

// TestExplorerTransactions_NoAdminGroups verifies that org contracts are hidden
// from anonymous users even when the org has NO admin groups at all.
// This is the regression test for the bug where org contract detection was
// coupled with admin group lookup — if no admin groups existed, the contract
// fell through as VisibilityFull.
func TestExplorerTransactions_NoAdminGroups(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// Create org with a contract — registerOrgContract creates a regular group
	// (is_org_admin=false) with a contract_grant that has no claims.
	// Deliberately do NOT create any admin group.
	privateAddr := "0xdddd000000000000000000000000000000000001"
	_ = registerOrgContract(t, database, privateAddr)

	publicFrom := "0xeeee000000000000000000000000000000000001"
	publicTo := "0xeeee000000000000000000000000000000000002"

	_, err := conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (100, '0xblock_noadmin', '0x0', 2000, 21000, 30000000, 3, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	// tx1: from org contract, contract creation — must be hidden
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_noadmin1', 100, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)

	// tx2: public to org contract — both-sides check: from is public, to is private
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_noadmin2', 100, 1, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, privateAddr)
	require.NoError(t, err)

	// tx3: public to public — always visible
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_noadmin3', 100, 2, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, publicTo)
	require.NoError(t, err)

	t.Run("anonymous sees only public tx despite no admin groups existing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		// tx1 dropped: contract creation from hidden deployer
		// tx2 survives SQL (only to is hidden, not both) but to-address gets redacted
		// tx3 fully visible
		assert.Equal(t, int64(2), total, "anonymous should see 2 txs: 1 public + 1 with redacted to-address")
		assert.Len(t, txs, 2)

		for _, tx := range txs {
			assert.NotEqual(t, privateAddr, strings.ToLower(tx.From),
				"org contract address must not appear as from even without admin groups")
		}
	})
}

func TestExplorerVisibility_TransactionShapes(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// --- Org A setup ---
	orgAID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, 'Org A', '{}')",
		orgAID, "orgA-"+orgAID[:8])
	require.NoError(t, err)

	orgAContract := "0xaa01000000000000000000000000000000000001"
	contractAID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Org A Contract')",
		contractAID, orgAID, orgAContract)
	require.NoError(t, err)

	groupAID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members-a', 'Members A', 0, 'members-a')",
		groupAID, orgAID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractAID, groupAID)
	require.NoError(t, err)

	adminGroupAID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins-a', 'Admins A', 0, 'admins-a', true)",
		adminGroupAID, orgAID)
	require.NoError(t, err)

	// --- Org B setup ---
	orgBID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, 'Org B', '{}')",
		orgBID, "orgB-"+orgBID[:8])
	require.NoError(t, err)

	orgBContract := "0xbb01000000000000000000000000000000000001"
	contractBID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Org B Contract')",
		contractBID, orgBID, orgBContract)
	require.NoError(t, err)

	groupBID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members-b', 'Members B', 0, 'members-b')",
		groupBID, orgBID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractBID, groupBID)
	require.NoError(t, err)

	adminGroupBID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins-b', 'Admins B', 0, 'admins-b', true)",
		adminGroupBID, orgBID)
	require.NoError(t, err)

	// --- Users ---
	aliceDID := "did:test:shapes_alice"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	addUserToGroup(t, database, aliceUserID, adminGroupAID)

	bobDID := "did:test:shapes_bob"
	_ = createTestUserForExplorer(t, database, bobDID)
	bobEOA := "0xcc01000000000000000000000000000000000001"
	err = database.SystemLinkEthAddress(ctx, bobDID, bobEOA)
	require.NoError(t, err)

	noMemberDID := "did:test:shapes_nomember"
	_ = createTestUserForExplorer(t, database, noMemberDID)

	// --- Public addresses ---
	pub1 := "0xdd01000000000000000000000000000000000001"
	pub2 := "0xdd02000000000000000000000000000000000002"

	// --- Block and transactions ---
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (200, '0xblock_shapes', '0x0', 3000, 21000, 30000000, 11, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	txInsert := `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ($1, 200, $2, $3, $4, 0, 21000, 1000, 1, '0x')`

	// tx1: Contract creation from orgA_contract (hidden deployer)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape01", 0, orgAContract, nil)
	require.NoError(t, err)
	// tx2: Contract creation from public address
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape02", 1, pub1, nil)
	require.NoError(t, err)
	// tx3: Both sides hidden (orgA → orgB)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape03", 2, orgAContract, orgBContract)
	require.NoError(t, err)
	// tx4: Hidden from (orgA), public to
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape04", 3, orgAContract, pub1)
	require.NoError(t, err)
	// tx5: Public from, hidden to (orgA)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape05", 4, pub1, orgAContract)
	require.NoError(t, err)
	// tx6: Both public
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape06", 5, pub1, pub2)
	require.NoError(t, err)
	// tx7: Hidden EOA from (bob), public to
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape07", 6, bobEOA, pub1)
	require.NoError(t, err)
	// tx8: Public from, hidden EOA to (bob)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape08", 7, pub1, bobEOA)
	require.NoError(t, err)
	// tx9: Hidden EOA from (bob), hidden contract to (orgA)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape09", 8, bobEOA, orgAContract)
	require.NoError(t, err)
	// tx10: Hidden contract from (orgA), hidden EOA to (bob)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape10", 9, orgAContract, bobEOA)
	require.NoError(t, err)
	// tx11: Contract creation from hidden EOA (bob)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_shape11", 10, bobEOA, nil)
	require.NoError(t, err)

	// --- Subtests ---

	t.Run("anonymous viewer", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=20", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		// Hidden = [orgAContract, orgBContract, bobEOA]
		// Dropped: tx1 (rule1), tx3 (rule2), tx9 (rule2), tx10 (rule2), tx11 (rule1)
		// Visible: tx2, tx4, tx5, tx6, tx7, tx8 = 6
		assert.Equal(t, int64(6), total, "anonymous should see 6 transactions")
		assert.Len(t, txs, 6)

		// Verify no transaction has both from and to in the hidden set
		hiddenSet := map[string]bool{
			orgAContract: true,
			orgBContract: true,
			bobEOA:       true,
		}
		for _, tx := range txs {
			fromHidden := hiddenSet[strings.ToLower(tx.From)]
			toHidden := tx.To != nil && hiddenSet[strings.ToLower(*tx.To)]
			assert.False(t, fromHidden && (tx.To == nil || toHidden),
				"transaction %s should not have hidden from with null/hidden to", tx.Hash)
		}
	})

	t.Run("alice (admin of orgA)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=20", nil)
		addBearerToken(t, req, srv, aliceDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		// Alice: orgAContract=Full, orgBContract=Redacted(hidden), bobEOA=Hidden
		// Hidden = [orgBContract, bobEOA]
		// Dropped: tx11 (rule1: bob hidden, to=NULL)
		// Visible: tx1-tx10 = 10
		assert.Equal(t, int64(10), total, "alice should see 10 transactions")
		assert.Len(t, txs, 10)
	})

	t.Run("bob (EOA owner)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=20", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		// Bob: bobEOA=Full, orgAContract=Redacted(hidden), orgBContract=Redacted(hidden)
		// Hidden = [orgAContract, orgBContract]
		// Dropped: tx1 (rule1: orgA hidden, to=NULL), tx3 (rule2: orgA+orgB both hidden)
		// Visible: tx2, tx4, tx5, tx6, tx7, tx8, tx9, tx10, tx11 = 9
		assert.Equal(t, int64(9), total, "bob should see 9 transactions")
		assert.Len(t, txs, 9)
	})

	t.Run("authenticated user with no memberships", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=20", nil)
		addBearerToken(t, req, srv, noMemberDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		// Same as anonymous: no org access, no EOA links
		// Hidden = [orgAContract, orgBContract, bobEOA]
		// Expected: 6
		assert.Equal(t, int64(6), total, "no-membership user should see same 6 as anonymous")
		assert.Len(t, txs, 6)
	})
}

func TestExplorerVisibility_ClaimCombinations(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// --- Org setup ---
	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, 'Claims Org', '{}')",
		orgID, "claims-org-"+orgID[:8])
	require.NoError(t, err)

	privContract := "0xee01000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Private Contract')",
		contractID, orgID, privContract)
	require.NoError(t, err)

	// Admin group (is_org_admin=true)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'claims-admin', 'Admin', 0, 'claims-admin', true)",
		adminGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{admin}')",
		uuid.New().String(), contractID, adminGroupID)
	require.NoError(t, err)

	// Helper to create a non-admin group with specific claims and a contract grant
	makeClaimsGroup := func(slug, claims string) string {
		gid := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, $3, $4, 0, $5, false)",
			gid, orgID, slug, "Group "+slug, slug)
		require.NoError(t, err)

		_, err = conn.ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, $4)",
			uuid.New().String(), contractID, gid, claims)
		require.NoError(t, err)

		return gid
	}

	readGroupID := makeClaimsGroup("claims-read", "{read}")
	writeGroupID := makeClaimsGroup("claims-write", "{write}")
	readWriteGroupID := makeClaimsGroup("claims-rw", "{read,write}")
	deployGroupID := makeClaimsGroup("claims-deploy", "{deploy}")
	rwdGroupID := makeClaimsGroup("claims-rwd", "{read,write,deploy}")
	fullClaimsGroupID := makeClaimsGroup("claims-full", "{read,write,deploy,admin}")
	noClaimsGroupID := makeClaimsGroup("claims-none", "{}")

	// --- Users ---
	type testUser struct {
		name          string
		did           string
		expectedTotal int64
	}

	// Create users and assign groups
	createAndAssign := func(_, did string, groupIDs ...string) {
		uid := createTestUserForExplorer(t, database, did)
		for _, gid := range groupIDs {
			addUserToGroup(t, database, uid, gid)
		}
	}

	createAndAssign("readUser", "did:test:claims_read", readGroupID)
	createAndAssign("writeUser", "did:test:claims_write", writeGroupID)
	createAndAssign("readWriteUser", "did:test:claims_rw", readWriteGroupID)
	createAndAssign("deployUser", "did:test:claims_deploy", deployGroupID)
	createAndAssign("readWriteDeployUser", "did:test:claims_rwd", rwdGroupID)
	createAndAssign("noClaimsUser", "did:test:claims_none", noClaimsGroupID)
	createAndAssign("fullClaimsUser", "did:test:claims_full", fullClaimsGroupID)
	createAndAssign("adminUser", "did:test:claims_admin", adminGroupID)
	createAndAssign("multiGroupUser", "did:test:claims_multi", readGroupID, adminGroupID)

	// --- Explorer data ---
	pubAddr := "0xff01000000000000000000000000000000000001"
	pubAddr2 := "0xff02000000000000000000000000000000000002"

	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (300, '0xblock_claims', '0x0', 4000, 21000, 30000000, 3, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	txInsert := `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ($1, 300, $2, $3, $4, 0, 21000, 1000, 1, '0x')`

	// tx1: Contract creation from private contract (hidden deployer)
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_claims01", 0, privContract, nil)
	require.NoError(t, err)
	// tx2: Public to private contract
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_claims02", 1, pubAddr, privContract)
	require.NoError(t, err)
	// tx3: Public to public
	_, err = conn.ExecContext(ctx, txInsert, "0xtx_claims03", 2, pubAddr, pubAddr2)
	require.NoError(t, err)

	// --- Table-driven subtests ---
	// Any user with a contract_grant on privContract gets VisibilityFull, so privContract
	// is NOT in the hidden set and all 3 txs are visible. The only difference is
	// is_org_admin (sees ALL org contracts without explicit grants) vs explicit grants.
	// Since all groups here have a contract_grant, all users see 3 transactions.
	cases := []testUser{
		{"readUser", "did:test:claims_read", 3},
		{"writeUser", "did:test:claims_write", 3},
		{"readWriteUser", "did:test:claims_rw", 3},
		{"deployUser", "did:test:claims_deploy", 3},
		{"readWriteDeployUser", "did:test:claims_rwd", 3},
		{"noClaimsUser", "did:test:claims_none", 3},
		{"fullClaimsUser (non-admin group with admin claim)", "did:test:claims_full", 3},
		{"adminUser (is_org_admin group)", "did:test:claims_admin", 3},
		{"multiGroupUser (read + admin groups)", "did:test:claims_multi", 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
			addBearerToken(t, req, srv, tc.did)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			total, txs := parsePaginatedResponse(t, w.Body.Bytes())
			assert.Equal(t, tc.expectedTotal, total, "%s: unexpected total", tc.name)
			assert.Len(t, txs, int(tc.expectedTotal), "%s: unexpected tx count", tc.name)
		})
	}
}

// parseBlocksResponse parses a json array of blocks
func parseBlocksResponse(t *testing.T, body []byte) []explorer.Block {
	t.Helper()
	var resp []explorer.Block
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp
}

func setupExplorerBlocksRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/blocks", srv.getExplorerBlocks)
	return router
}

func TestExplorerBlocks_VisibilityFiltering(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupExplorerBlocksRouter(srv)
	ctx := context.Background()

	// --- RBAC setup ---
	privateAddr := "0xaaaa000000000000000000000000000000000001"
	groupID := registerOrgContract(t, database, privateAddr)

	aliceDID := "did:test:alice"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	
	// Create an admin group for Alice so she gets VisibilityFull
	adminGroupID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins', 'Admins', 0, 'admins', true)",
		adminGroupID, groupID)
	require.NoError(t, err)

	addUserToGroup(t, database, aliceUserID, adminGroupID)

	// --- Explorer data setup ---
	publicFrom := "0xbbbb000000000000000000000000000000000001"
	publicTo := "0xbbbb000000000000000000000000000000000002"

	// Block 10: 2 private txs, 2 public txs. Total stored in block = 4.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (10, '0xblock10', '0x0', 1000, 21000, 30000000, 4, '0xminer', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx, `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ('0xtx1', 10, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ('0xtx2', 10, 1, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ('0xtx3', 10, 2, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, publicTo)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ('0xtx4', 10, 3, $1, $2, 0, 21000, 1000, 1, '0x')`, publicFrom, publicTo)
	require.NoError(t, err)

	// Block 11: 1 private tx, 0 public txs. Total stored = 1.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (11, '0xblock11', '0xblock10', 1005, 21000, 30000000, 1, '0xminer', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data) VALUES ('0xtx5', 11, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)

	t.Run("anonymous viewer sees filtered block transaction counts", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/blocks", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			require.FailNowf(t, "expected status OK", "Got status %d, body: %s", w.Code, w.Body.String())
		}
		
		blocks := parseBlocksResponse(t, w.Body.Bytes())
		require.Len(t, blocks, 2)
		
		// Expected order is descending (Block 11 then Block 10)
		assert.Equal(t, uint64(11), blocks[0].Number)
		assert.Equal(t, 0, blocks[0].TransactionCount, "anonymous should see 0 txs in block 11")

		assert.Equal(t, uint64(10), blocks[1].Number)
		assert.Equal(t, 2, blocks[1].TransactionCount, "anonymous should see 2 public txs out of 4 in block 10")
	})

	t.Run("authenticated org member sees all transaction counts", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/blocks", nil)
		addBearerToken(t, req, srv, aliceDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		
		blocks := parseBlocksResponse(t, w.Body.Bytes())
		require.Len(t, blocks, 2)
		
		assert.Equal(t, uint64(11), blocks[0].Number)
		assert.Equal(t, 1, blocks[0].TransactionCount)

		assert.Equal(t, uint64(10), blocks[1].Number)
		assert.Equal(t, 4, blocks[1].TransactionCount)
	})
}
