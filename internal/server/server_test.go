package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupTestServer(t *testing.T) *Server {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development (no external PostgreSQL needed)
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Reset database (drops all tables and runs migrations)
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	cfg := &config.Config{
		NodeURL: "http://localhost:8545",
	}

	proxySvc := proxy.New(cfg.NodeURL)
	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)

	return &Server{
		db:             database,
		rbacAccessCtrl: rbacAccessCtrl,
		proxy:          proxySvc,
	}
}

func TestLocalhostOnlyMiddleware(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Set trusted proxies for tests (same as production)
	router.SetTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"})

	api := router.Group("/api")
	api.Use(srv.localhostOnlyMiddleware())
	api.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	tests := []struct {
		name           string
		setupRequest   func(*http.Request)
		expectedStatus int
	}{
		{
			name: "localhost IPv4",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "127.0.0.1:12345"
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "localhost IPv6",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "[::1]:12345"
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Docker network IP (from host)",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "172.17.0.1:12345" // Docker gateway
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Docker custom network IP (from frontend container)",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "192.168.117.6:12345" // Docker custom network
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "X-Forwarded-For localhost",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "172.17.0.1:12345"
				req.Header.Set("X-Forwarded-For", "127.0.0.1")
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "X-Real-IP localhost",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "172.17.0.1:12345"
				req.Header.Set("X-Real-IP", "127.0.0.1")
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "external IP",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "203.0.113.1:12345" // Public IP
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "X-Forwarded-For external IP",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "172.17.0.1:12345"
				req.Header.Set("X-Forwarded-For", "203.0.113.1")
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "External IP trying to spoof X-Forwarded-For",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "203.0.113.1:12345"           // External attacker
				req.Header.Set("X-Forwarded-For", "127.0.0.1") // Trying to spoof localhost
			},
			expectedStatus: http.StatusForbidden, // Should be blocked - external IP not trusted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/test", nil)
			tt.setupRequest(req)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
