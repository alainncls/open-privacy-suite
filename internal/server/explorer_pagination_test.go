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

	t.Run("non-admin org member sees same as anonymous", func(t *testing.T) {
		// Eve is a member of a NON-admin group with only 'read' claim on the contract.
		// Since she is not admin, the org contract is VisibilityRedacted for her,
		// and none of the test transactions have Eve as from/to, so she should see
		// exactly the same filtered results as anonymous.
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
		assert.Equal(t, int64(3), total, "non-admin org member (Eve) should see only 3 public transactions, same as anonymous")
		assert.Len(t, txs, 3, "page should contain the same 3 visible transactions as anonymous")

		for _, tx := range txs {
			assert.NotEqual(t, privateAddr, strings.ToLower(tx.From), "private contract address must not appear for non-admin member")
			assert.NotEqual(t, privateUserAddr, strings.ToLower(tx.From), "private user address must not appear for non-admin member")
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
