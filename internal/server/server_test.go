package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"privacy-proxy/internal/access"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/proxy"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupTestServer(t *testing.T) *Server {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
	}
	
	// Ensure test database exists
	if err := db.EnsureTestDatabase(dbURL); err != nil {
		t.Logf("Warning: Could not ensure test database exists: %v", err)
		t.Logf("Please create the database manually: createdb privacy_proxy_test")
		// Continue anyway - might already exist
	}
	
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	
	// Clean up tables
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Migrate()
	
	cfg := &config.Config{
		NodeURL:     "http://localhost:8545",
		DatabaseURL: dbURL,
		BillionsURL: "http://localhost:9000",
	}
	
	identitySvc := identity.NewService(cfg.BillionsURL)
	accessCtrl := access.NewController(database)
	proxySvc := proxy.New(cfg.NodeURL)
	
	return &Server{
		db:          database,
		identitySvc: identitySvc,
		accessCtrl:  accessCtrl,
		proxy:       proxySvc,
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
				req.RemoteAddr = "203.0.113.1:12345" // External attacker
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

func TestListPolicies_LocalhostOnly(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.db.Close()
	
	// Create a test policy
	policy := &db.AccessPolicy{
		ExternalID:   "billions:test_user",
		KYC:          true,
		AllowMethods: []string{"eth_call"},
		Banned:       false,
	}
	srv.db.SetPolicy(policy)
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.SetTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"})
	
	api := router.Group("/api")
	api.Use(srv.localhostOnlyMiddleware())
	api.GET("/policies", srv.listPolicies)
	
	// Test from localhost - should succeed
	req := httptest.NewRequest("GET", "/api/policies", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	
	// Test from external IP - should fail
	req2 := httptest.NewRequest("GET", "/api/policies", nil)
	req2.RemoteAddr = "203.0.113.1:12345" // Public IP
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w2.Code)
	}
}

func TestCreatePolicy_LocalhostOnly(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.db.Close()
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.SetTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"})
	
	api := router.Group("/api")
	api.Use(srv.localhostOnlyMiddleware())
	api.POST("/policies", srv.createPolicy)
	
	policyData := map[string]interface{}{
		"external_id":   "billions:new_user",
		"kyc":           true,
		"allow_methods": []string{"eth_call"},
		"banned":        false,
	}
	
	jsonData, _ := json.Marshal(policyData)
	
	// Test from localhost - should succeed
	req := httptest.NewRequest("POST", "/api/policies", bytes.NewReader(jsonData))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	
	// Test from external IP - should fail
	req2 := httptest.NewRequest("POST", "/api/policies", bytes.NewReader(jsonData))
	req2.RemoteAddr = "203.0.113.1:12345" // Public IP
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w2.Code)
	}
}
