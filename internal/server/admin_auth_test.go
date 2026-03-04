package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAdminAuthTestServer creates a test server with a real database, JWT
// service, and the admin auth middleware wired up.
func setupAdminAuthTestServer(t *testing.T, adminToken string) (*Server, *gin.Engine) {
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

	cfg := &config.Config{
		AdminAPIToken: adminToken,
	}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}

	router := gin.New()

	// Admin routes behind adminAuthMiddleware (matches production setup).
	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	admin.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok":          true,
			"auth_method": c.GetString("auth_method"),
		})
	})

	// /me routes behind JWTAuthMiddleware (matches production setup).
	srv.registerUserProfileRoutes(router)

	t.Cleanup(func() { srv.db.Close() })

	return srv, router
}

// createTestUserWithClaims creates a user, org, group, membership, and group
// access with the given claims.  Returns the user's external ID (DID).
func createTestUserWithClaims(t *testing.T, srv *Server, claims []rbac.Claim) string {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "test-org-" + uuid.New().String()[:8],
		Name: "Test Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "test-group-" + uuid.New().String()[:8],
		Name:  "Test Group",
		Path:  "test-group",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         claims,
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	userDID := "did:test:" + uuid.New().String()[:8]
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	return userDID
}

// ---------------------------------------------------------------------------
// Tests: adminAuthMiddleware
// ---------------------------------------------------------------------------

func TestAdminAuth_XAdminToken_StillWorks(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("X-Admin-Token", "my-secret-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "admin_token", body["auth_method"])
}

func TestAdminAuth_XAdminToken_WrongValueDenied(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("X-Admin-Token", "wrong-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_JWT_AdminClaimGrantsAccess(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimAdmin})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "jwt_admin", body["auth_method"])
}

func TestAdminAuth_JWT_NoAdminClaimGets403(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimRead, rbac.ClaimWrite})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestAdminAuth_NoAuthGets401(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_InvalidJWTGets401(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_ExpiredJWTGets401(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	// Create a JWT service with 0 TTL to produce expired tokens immediately.
	expiredJWT, err := auth.NewJWTService("test-secret", "test-refresh-secret", 0, time.Hour)
	require.NoError(t, err)

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimAdmin})
	token, err := expiredJWT.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// Small sleep to ensure the token is past its expiry.
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_NoTokenConfigured_AllowsRequest(t *testing.T) {
	// Dev mode: ADMIN_API_TOKEN is empty, no credentials needed.
	_, router := setupAdminAuthTestServer(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: /me/admin-status endpoint
// ---------------------------------------------------------------------------

func TestAdminStatus_AdminUser(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimAdmin})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, true, body["is_admin"])
}

func TestAdminStatus_NonAdminUser(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimRead})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, false, body["is_admin"])
}

func TestAdminStatus_UserNotInDB(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "")

	// Create token for a DID that does not exist in the database.
	token, err := srv.jwtService.IssueAccessToken("did:test:nonexistent", true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, false, body["is_admin"])
}

func TestAdminStatus_Unauthenticated(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
