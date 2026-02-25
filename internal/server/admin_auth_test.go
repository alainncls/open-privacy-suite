package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/config"

	"github.com/gin-gonic/gin"
)

func newAdminAuthTestRouter(s *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	admin := router.Group("/api/v1/admin")
	admin.Use(s.adminAuthMiddleware())
	admin.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

func TestAdminAuthMiddleware_NoTokenConfigured_AllowsRequest(t *testing.T) {
	s := &Server{
		config: &config.Config{},
	}
	router := newAdminAuthTestRouter(s)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestAdminAuthMiddleware_TokenConfigured_RequiresToken(t *testing.T) {
	s := &Server{
		config: &config.Config{AdminAPIToken: "test-admin-token"},
	}
	router := newAdminAuthTestRouter(s)

	tests := []struct {
		name           string
		setupRequest   func(req *http.Request)
		expectedStatus int
	}{
		{
			name:           "missing token denied",
			setupRequest:   func(req *http.Request) {},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "wrong X-Admin-Token denied",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-Admin-Token", "wrong-token")
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "correct X-Admin-Token allowed",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-Admin-Token", "test-admin-token")
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "correct bearer token allowed",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer test-admin-token")
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "wrong bearer token denied",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer wrong-token")
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
			tc.setupRequest(req)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Fatalf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
		})
	}
}
