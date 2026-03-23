package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	// Create user alice as a member of the org's group.
	aliceDID := "did:test:alice"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	addUserToGroup(t, database, aliceUserID, groupID)

	// Create user bob and link an EOA to him.
	bobDID := "did:test:bob"
	_ = createTestUserForExplorer(t, database, bobDID)
	privateUserAddr := "0xcccc000000000000000000000000000000000001"
	err := database.SystemLinkEthAddress(ctx, bobDID, privateUserAddr)
	require.NoError(t, err)

	// --- Explorer data setup ---

	publicFrom := "0xbbbb000000000000000000000000000000000001"
	publicTo := "0xbbbb000000000000000000000000000000000002"

	// Insert a block with 7 transactions.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		 VALUES (1, '0xblockhash_pag1', '0x0', 1000, 21000, 30000000, 7)`)
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
