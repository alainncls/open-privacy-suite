package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGetLogsTestServer wires up just enough of the Server to exercise the
// /api/v1/admin/logs handler against a real Postgres. The X-Admin-Token path
// bypasses JWT/org-scoping so the test focuses on the handler's parsing and
// pass-through behaviour.
func setupGetLogsTestServer(t *testing.T) (*Server, *gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

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

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	const adminToken = "test-admin-token"
	cfg := &config.Config{AdminAPIToken: adminToken}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}

	router := gin.New()
	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	admin.GET("/logs", srv.getLogs)

	t.Cleanup(func() { srv.db.Close() })
	return srv, router, adminToken
}

// doGetLogs issues a GET /api/v1/admin/logs?<query> with the X-Admin-Token
// header set and returns the recorded response.
func doGetLogs(t *testing.T, router *gin.Engine, token string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/admin/logs"
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Admin-Token", token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestGetLogsHandler exercises the admin /logs endpoint end-to-end against a
// real Postgres. Each sub-test owns its own seed data; the handler returns
// rows ordered by created_at DESC.
func TestGetLogsHandler(t *testing.T) {
	srv, router, token := setupGetLogsTestServer(t)
	ctx := context.Background()

	// Seed a small catalogue of rows that lets us exercise every filter
	// dimension. Inserts run in order so id and created_at both increase.
	type seedRow struct {
		externalID    string
		method        string
		statusCode    int
		correlationID string
	}
	seed := []seedRow{
		{"did:test:alice", "eth_call", 200, "corr-A"},
		{"did:test:alice", "eth_blockNumber", 200, "corr-B"},
		{"did:test:bob", "eth_call", 401, "corr-A"},
		{"did:test:bob", "eth_call", 200, "corr-C"},
		{"did:test:carol", "eth_getLogs", 500, ""},
	}
	insertedIDs := make([]int64, 0, len(seed))
	for _, r := range seed {
		id, _, err := srv.db.LogAccessEnhanced(ctx, r.externalID, r.method, r.statusCode, "127.0.0.1", r.correlationID, nil, nil)
		require.NoError(t, err)
		insertedIDs = append(insertedIDs, id)
	}

	t.Run("no filters returns default page", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data   []map[string]any `json:"data"`
			Total  int64            `json:"total"`
			Limit  int              `json:"limit"`
			Offset int              `json:"offset"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

		assert.Equal(t, 100, body.Limit, "default limit")
		assert.Equal(t, 0, body.Offset, "default offset")
		assert.Equal(t, int64(len(seed)), body.Total)
		assert.Len(t, body.Data, len(seed))
	})

	t.Run("all filters together pass through to DB layer", func(t *testing.T) {
		// alice + eth_call + corr-A + status_code=200 → exactly one row.
		from := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
		to := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
		q := url.Values{
			"external_id":    []string{"did:test:alice"},
			"method":         []string{"eth_call"},
			"status_code":    []string{"200"},
			"correlation_id": []string{"corr-A"},
			"from":           []string{from},
			"to":             []string{to},
			"limit":          []string{"50"},
			"offset":         []string{"0"},
		}
		rec := doGetLogs(t, router, token, q)
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data   []map[string]any `json:"data"`
			Total  int64            `json:"total"`
			Limit  int              `json:"limit"`
			Offset int              `json:"offset"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Len(t, body.Data, 1, "all filters together should narrow to one row")
		assert.Equal(t, "did:test:alice", body.Data[0]["external_id"])
		assert.Equal(t, "eth_call", body.Data[0]["method"])
		assert.EqualValues(t, 200, body.Data[0]["status_code"])
		assert.Equal(t, int64(1), body.Total)
		assert.Equal(t, 50, body.Limit)
		assert.Equal(t, 0, body.Offset)
	})

	t.Run("invalid status_code rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"status_code": []string{"abc"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid status_code", body["error"])
	})

	t.Run("non-positive status_code rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"status_code": []string{"0"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid status_code", body["error"])
	})

	t.Run("invalid from timestamp rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"from": []string{"not-a-date"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid from timestamp; expected RFC3339", body["error"])
	})

	t.Run("invalid to timestamp rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"to": []string{"not-a-date"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid to timestamp; expected RFC3339", body["error"])
	})

	t.Run("limit clamped at MaxAccessLogQueryLimit", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"limit": []string{"99999"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Limit int `json:"limit"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, db.MaxAccessLogQueryLimit, body.Limit, "limit must be clamped")
	})

	t.Run("negative limit falls through to default", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"limit": []string{"-5"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Limit int `json:"limit"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, 100, body.Limit, "negative limit ignored, default 100 applied")
	})

	t.Run("negative offset defaults to 0", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"offset": []string{"-3"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Offset int `json:"offset"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, 0, body.Offset, "negative offset ignored, default 0 applied")
	})

	t.Run("each individual filter narrows results correctly", func(t *testing.T) {
		// external_id alone
		rec := doGetLogs(t, router, token, url.Values{"external_id": []string{"did:test:bob"}})
		require.Equal(t, http.StatusOK, rec.Code)
		var body struct {
			Data  []map[string]any `json:"data"`
			Total int64            `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(2), body.Total)
		for _, row := range body.Data {
			assert.Equal(t, "did:test:bob", row["external_id"])
		}

		// method alone
		rec = doGetLogs(t, router, token, url.Values{"method": []string{"eth_getLogs"}})
		require.Equal(t, http.StatusOK, rec.Code)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(1), body.Total)

		// status_code alone
		rec = doGetLogs(t, router, token, url.Values{"status_code": []string{"500"}})
		require.Equal(t, http.StatusOK, rec.Code)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(1), body.Total)
	})
}
