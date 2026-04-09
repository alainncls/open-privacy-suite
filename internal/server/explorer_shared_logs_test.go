package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// explorerSchemaWithLogs extends the base explorer schema with a logs table.
const explorerSchemaWithLogs = `
CREATE TABLE IF NOT EXISTS blocks (
    number BIGINT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    parent_hash TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    gas_used BIGINT NOT NULL,
    gas_limit BIGINT NOT NULL,
    base_fee_per_gas BIGINT,
    transaction_count INT NOT NULL,
    size BIGINT DEFAULT 0,
    difficulty TEXT DEFAULT '0',
    total_difficulty TEXT DEFAULT '0',
    nonce TEXT DEFAULT '0x0000000000000000',
    miner TEXT,
    extra_data TEXT,
    state_root TEXT,
    transactions_root TEXT,
    receipts_root TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    hash TEXT PRIMARY KEY,
    block_number BIGINT NOT NULL REFERENCES blocks(number) ON DELETE CASCADE,
    tx_index INT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT,
    value NUMERIC(78, 0) NOT NULL,
    gas_used BIGINT NOT NULL,
    gas_price BIGINT NOT NULL,
    gas_limit BIGINT,
    max_fee_per_gas BIGINT,
    max_priority_fee_per_gas BIGINT,
    nonce BIGINT,
    tx_type SMALLINT DEFAULT 0,
    input_data TEXT,
    status SMALLINT NOT NULL,
    error TEXT,
    revert_reason TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL,
    log_index INT NOT NULL,
    address TEXT NOT NULL,
    topic0 TEXT,
    topic1 TEXT,
    topic2 TEXT,
    topic3 TEXT,
    data TEXT NOT NULL DEFAULT '0x',
    block_number BIGINT NOT NULL,
    timestamp BIGINT,
    removed BOOLEAN NOT NULL DEFAULT false
);
`

// setupTestServerForSharedLogs creates a test server with explorer store configured,
// including the logs table needed for the shared-logs endpoint.
func setupTestServerForSharedLogs(t *testing.T) (*Server, *db.DB, *explorer.Store) {
	t.Helper()

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, db.ResetTestDatabase(database))

	// Create explorer tables (including logs) and truncate for isolation.
	_, err = database.Conn().ExecContext(context.Background(), explorerSchemaWithLogs)
	require.NoError(t, err, "failed to create explorer schema")
	_, err = database.Conn().ExecContext(context.Background(),
		"TRUNCATE logs, transactions, blocks CASCADE")
	require.NoError(t, err, "failed to truncate explorer tables")

	explorerStore, err := explorer.NewStore(dbURL)
	require.NoError(t, err)

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

	srv := &Server{
		db:                database,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbac.NewAccessController(database, 5*time.Minute),
		disclosureService: disclosure.NewService(database),
		config:            cfg,
		explorerStore:     explorerStore,
		explorerRedactor:  explorer.NewRedactionEngine(explorerStore, database),
	}

	t.Cleanup(func() {
		explorerStore.Close()
		srv.db.Close()
	})

	return srv, database, explorerStore
}

// setupSharedLogsRouter creates a gin router with the shared-logs endpoint.
func setupSharedLogsRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/shared-logs", srv.getSharedLogs)
	return router
}

// seedBlockAndTx seeds a block and transaction into the explorer DB and returns the tx hash.
func seedBlockAndTx(t *testing.T, conn *sql.DB, blockNum int64, txHash, from, to string) {
	t.Helper()
	blockHash := "0xblock" + txHash[6:] // derive unique block hash
	_, err := conn.ExecContext(context.Background(), `
		INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		VALUES ($1, $2, '0x0', $3, 21000, 15000000, 1)
		ON CONFLICT (number) DO NOTHING`,
		blockNum, blockHash, time.Now().Unix())
	require.NoError(t, err)

	_, err = conn.ExecContext(context.Background(), `
		INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status)
		VALUES ($1, $2, 0, $3, $4, 0, 21000, 1000000000, 1)
		ON CONFLICT (hash) DO NOTHING`,
		txHash, blockNum, from, to)
	require.NoError(t, err)
}

// seedLog inserts a log entry into the explorer DB.
func seedLog(t *testing.T, conn *sql.DB, txHash string, logIndex int, address string, blockNum int64, topic0 string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), `
		INSERT INTO logs (tx_hash, log_index, address, topic0, data, block_number, timestamp)
		VALUES ($1, $2, $3, $4, '0x', $5, $6)`,
		txHash, logIndex, address, topic0, blockNum, time.Now().Unix())
	require.NoError(t, err)
}

func TestSharedLogs_RequiresAuth(t *testing.T) {
	srv, _, _ := setupTestServerForSharedLogs(t)
	router := setupSharedLogsRouter(srv)

	// Anonymous request (no JWT) should get 401.
	req := httptest.NewRequest("GET", "/api/v1/explorer/shared-logs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "JWT authentication required")
}

func TestSharedLogs_ViewerSeesSharedTxLogs(t *testing.T) {
	srv, database, _ := setupTestServerForSharedLogs(t)
	router := setupSharedLogsRouter(srv)

	viewerDID := "did:privado:shared_viewer"
	senderDID := "did:privado:shared_sender"
	orgID := "org-shared-1"

	// Create viewer user (needed for JWT validation).
	createTestUserForExplorer(t, database, viewerDID)

	txHash := "0xshared1111111111111111111111111111111111111111111111111111111111"
	contractAddr := "0xcontract1111111111111111111111111111111111"
	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" // Transfer

	// Seed explorer data: block, tx, and log.
	conn := database.Conn()
	seedBlockAndTx(t, conn, 100, txHash, senderDID, contractAddr)
	seedLog(t, conn, txHash, 0, contractAddr, 100, topic0)

	// Save logVisibleTo: viewer can see logs for this tx.
	err := database.SaveTxLogVisibility(context.Background(), txHash, []string{viewerDID}, senderDID, orgID)
	require.NoError(t, err)

	// Request as the viewer.
	req := httptest.NewRequest("GET", "/api/v1/explorer/shared-logs", nil)
	addBearerToken(t, req, srv, viewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp SharedLogsResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 20, resp.Limit)
	assert.Equal(t, 0, resp.Offset)
	require.Len(t, resp.SharedLogs, 1)

	entry := resp.SharedLogs[0]
	assert.Equal(t, txHash, entry.TxHash)
	assert.Equal(t, uint64(100), entry.BlockNumber)
	assert.Equal(t, contractAddr, entry.ContractAddress)
	assert.NotEmpty(t, entry.SharedAt)
	require.Len(t, entry.Logs, 1)
	assert.Equal(t, contractAddr, entry.Logs[0].Address)
	assert.NotNil(t, entry.Logs[0].Topic0)
	assert.Equal(t, topic0, *entry.Logs[0].Topic0)
}

func TestSharedLogs_NonViewerGetsEmpty(t *testing.T) {
	srv, database, _ := setupTestServerForSharedLogs(t)
	router := setupSharedLogsRouter(srv)

	viewerDID := "did:privado:shared_viewer2"
	otherDID := "did:privado:shared_other"
	senderDID := "did:privado:shared_sender2"

	// Create both users.
	createTestUserForExplorer(t, database, viewerDID)
	createTestUserForExplorer(t, database, otherDID)

	txHash := "0xshared2222222222222222222222222222222222222222222222222222222222"

	// Save logVisibleTo: only viewerDID can see this tx.
	err := database.SaveTxLogVisibility(context.Background(), txHash, []string{viewerDID}, senderDID, "org-1")
	require.NoError(t, err)

	// Request as otherDID — should get empty result.
	req := httptest.NewRequest("GET", "/api/v1/explorer/shared-logs", nil)
	addBearerToken(t, req, srv, otherDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp SharedLogsResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, resp.SharedLogs)
}

func TestSharedLogs_Pagination(t *testing.T) {
	srv, database, _ := setupTestServerForSharedLogs(t)
	router := setupSharedLogsRouter(srv)

	viewerDID := "did:privado:shared_pager"
	createTestUserForExplorer(t, database, viewerDID)

	conn := database.Conn()

	// Create 3 shared txs.
	txHashes := []string{
		"0xpage1111111111111111111111111111111111111111111111111111111111111",
		"0xpage2222222222222222222222222222222222222222222222222222222222222",
		"0xpage3333333333333333333333333333333333333333333333333333333333333",
	}
	contractAddr := "0xcontract2222222222222222222222222222222222"

	for i, txHash := range txHashes {
		blockNum := int64(200 + i)
		seedBlockAndTx(t, conn, blockNum, txHash, "0xsender", contractAddr)
		seedLog(t, conn, txHash, 0, contractAddr, blockNum, "0xevent_topic")

		err := database.SaveTxLogVisibility(context.Background(), txHash, []string{viewerDID}, "did:sender", "org-1")
		require.NoError(t, err)
	}

	// Request page 1 (limit=2, offset=0).
	req := httptest.NewRequest("GET", "/api/v1/explorer/shared-logs?limit=2&offset=0", nil)
	addBearerToken(t, req, srv, viewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp SharedLogsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 3, resp.Total)
	assert.Equal(t, 2, resp.Limit)
	assert.Equal(t, 0, resp.Offset)
	require.Len(t, resp.SharedLogs, 2)

	// Request page 2 (limit=2, offset=2).
	req = httptest.NewRequest("GET", "/api/v1/explorer/shared-logs?limit=2&offset=2", nil)
	addBearerToken(t, req, srv, viewerDID)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 3, resp.Total)
	require.Len(t, resp.SharedLogs, 1)
}
