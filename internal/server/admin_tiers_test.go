package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// setupTieredAdminTestServer creates a test server with admin auth, org scoping,
// and RBAC routes wired up for testing the 3-tier admin model.
func setupTieredAdminTestServer(t *testing.T, adminToken string) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dbURL, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)

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

	adminAuth := srv.adminAuthMiddleware()
	orgScope := srv.orgScopingMiddleware()

	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware(), orgScope)
	{
		admin.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true, "auth_method": c.GetString("auth_method")})
		})
		srv.registerRBACRoutes(admin)
	}

	// /me routes
	me := router.Group("/api/v1/me")
	me.Use(auth.JWTAuthMiddleware(srv.jwtService, srv.db))
	{
		me.GET("/admin-status", srv.getMyAdminStatus)
	}

	_ = adminAuth // used in the admin.Use() chain

	t.Cleanup(func() { srv.db.Close() })

	return srv, router
}

// createOrgAndAdminUser creates an org with an org admin user. Returns (userDID, orgID, userID).
func createOrgAndAdminUser(t *testing.T, srv *Server) (string, string, string) {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "org-" + uuid.New().String()[:8],
		Name: "Test Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "org-admins-" + uuid.New().String()[:8],
		Name:       "Org Admins",
		Path:       "org-admins",
		IsOrgAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
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

	return userDID, org.ID, user.ID
}

// ---------------------------------------------------------------------------
// Tests: IsOrgAdmin DB function
// ---------------------------------------------------------------------------

func TestIsOrgAdmin_TrueForOrgAdminGroup(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()

	_, orgID, userID := createOrgAndAdminUser(t, srv)

	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, userID)
	require.NoError(t, err)
	assert.True(t, isOrgAdmin, "user in is_org_admin group must be detected as org admin")
	assert.Contains(t, orgIDs, orgID)
}

func TestIsOrgAdmin_FalseForAdminClaimOnly(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()

	// Create a user with admin claim but NOT is_org_admin
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "claim-org-" + uuid.New().String()[:8],
		Name: "Claim Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "admin-group-" + uuid.New().String()[:8],
		Name:       "Admin Group",
		Path:       "admin-group",
		IsOrgAdmin: false, // NOT org admin
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin}, // has admin claim
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:" + uuid.New().String()[:8],
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

	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, isOrgAdmin, "user with admin claim but NOT is_org_admin must NOT be detected as org admin")
	assert.Empty(t, orgIDs)
}

func TestIsOrgAdmin_ExpiredMembershipIgnored(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "exp-org-" + uuid.New().String()[:8],
		Name: "Expired Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "exp-admins-" + uuid.New().String()[:8],
		Name:       "Expired Admins",
		Path:       "exp-admins",
		IsOrgAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:expired-" + uuid.New().String()[:8],
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	pastTime := time.Now().Add(-24 * time.Hour)
	membership := &rbac.UserMembership{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		GroupID:   group.ID,
		Source:    rbac.MembershipSourceAdmin,
		ExpiresAt: &pastTime,
	}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, isOrgAdmin, "expired membership must not grant org admin")
	assert.Empty(t, orgIDs)
}

// ---------------------------------------------------------------------------
// Tests: Org scoping middleware
// ---------------------------------------------------------------------------

func TestOrgScoping_JWTAdminCanAccessOwnOrg(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+orgID+"/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOrgScoping_JWTAdminCannotAccessOtherOrg(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, _, _ := createOrgAndAdminUser(t, srv)

	// Create a second org that the user does NOT admin
	otherOrg := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "other-org-" + uuid.New().String()[:8],
		Name: "Other Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, otherOrg))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+otherOrg.ID+"/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied to this organization")
}

func TestOrgScoping_SuperAdminBypassesOrgScoping(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Create an org
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "super-org-" + uuid.New().String()[:8],
		Name: "Super Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+org.ID+"/groups", nil)
	req.Header.Set("X-Admin-Token", "secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOrgScoping_JWTAdminDeniedCrossOrgEndpoints(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, _, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// Cross-org endpoints (no :org_id in path) require super admin
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "super admin required")
}

// ---------------------------------------------------------------------------
// Tests: Escalation prevention (is_org_admin flag)
// ---------------------------------------------------------------------------

func TestEscalation_JWTAdminCannotCreateOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":         "new-admin-group",
		"name":         "New Admin Group",
		"is_org_admin": true, // Trying to escalate
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "only super admin can create org admin groups")
}

func TestEscalation_JWTAdminCanCreateNonAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":         "normal-group",
		"name":         "Normal Group",
		"is_org_admin": false, // Not escalating
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestEscalation_SuperAdminCanCreateOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "super-create-org-" + uuid.New().String()[:8],
		Name: "Super Create Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	body := map[string]interface{}{
		"slug":         "new-org-admin",
		"name":         "New Org Admin",
		"is_org_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+org.ID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestEscalation_JWTAdminCannotUpdateGroupToOrgAdmin(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	// Create a normal group to try updating
	normalGroup := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgID,
		Slug:  "normal-" + uuid.New().String()[:8],
		Name:  "Normal",
		Path:  "normal",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"is_org_admin": true, // Trying to escalate
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+normalGroup.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "only super admin can set org admin status")
}

func TestEscalation_JWTAdminCanUpdateGroupName(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	// Create a normal group to update
	normalGroup := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgID,
		Slug:  "updatable-" + uuid.New().String()[:8],
		Name:  "Old Name",
		Path:  "updatable",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"name": "New Name",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+normalGroup.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, "New Name", result["name"])
}

func TestEscalation_JWTAdminCanCreateGroupWithAdminClaim(t *testing.T) {
	// Org admins CAN create groups with admin claim (tier 3) — they just
	// cannot set is_org_admin on those groups.
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// First create the group
	groupBody := map[string]interface{}{
		"slug":         "contract-admins",
		"name":         "Contract Admins",
		"is_org_admin": false,
	}
	groupBytes, _ := json.Marshal(groupBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(groupBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var createdGroup map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &createdGroup))
	groupID := createdGroup["id"].(string)

	// Then set access with admin claim
	accessBody := map[string]interface{}{
		"allowed_methods": []string{"eth_call", "eth_sendTransaction"},
		"claims":          []string{"admin"},
	}
	accessBytes, _ := json.Marshal(accessBody)

	req = httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", bytes.NewReader(accessBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"org admin must be able to create groups with admin claim (tier 3 contract admin)")
}
