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

func TestOrgScoping_JWTAdminCanAccessGenericRoutes(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, _, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// Generic routes (no :org_id) are allowed for JWT org admins —
	// they don't expose cross-org data.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
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
	assert.Contains(t, w.Body.String(), errCreateOrgAdminGroupSuperOnly)
}

func TestEscalation_JWTAdminCanCreateReadonlyAdminGroup(t *testing.T) {
	// RD-866 + RD-917 §2: tier-2 admins can mint is_org_readonly_admin
	// groups within their own org. RO-admin is a strict subset of tier-2,
	// so granting it is delegation (not escalation). Only is_org_admin
	// remains super-admin-only.
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":                  "auditors",
		"name":                  "Auditors",
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
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
	assert.Contains(t, w.Body.String(), errSetOrgAdminStatusSuperOnly)
}

func TestEscalation_JWTAdminCanUpdateGroupToReadonlyAdmin(t *testing.T) {
	// Mirror of TestEscalation_JWTAdminCanCreateReadonlyAdminGroup for the
	// PUT path. RD-866 + RD-917 §2.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

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
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+normalGroup.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
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

// ---------------------------------------------------------------------------
// Tests: tighter is_org_admin demote / delete gate (RD-917 §2 follow-up)
// ---------------------------------------------------------------------------

func TestEscalation_JWTAdminCannotDemoteOrgAdminGroup(t *testing.T) {
	// A tier-2 admin sending {"is_org_admin": false} on an existing
	// is_org_admin=true group must be rejected with 403. Demoting an admin
	// group strips admin status from every member (potentially including
	// the demoter), causing an org-wide DoS that only super-admin can
	// recover from. Symmetric with the promote-to-true gate.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	// The org-admin group already exists from createOrgAndAdminUser; locate it.
	groups, err := srv.db.ListGroups(ctx, orgID)
	require.NoError(t, err)
	var orgAdminGroupID string
	for _, g := range groups {
		if g.IsOrgAdmin {
			orgAdminGroupID = g.ID
			break
		}
	}
	require.NotEmpty(t, orgAdminGroupID, "test fixture must include an is_org_admin group")

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"is_org_admin": false, // attempting to demote
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGroupID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errSetOrgAdminStatusSuperOnly)

	// Verify the flag is still true — gate fired before any DB write.
	g, err := srv.db.GetGroup(ctx, orgAdminGroupID)
	require.NoError(t, err)
	assert.True(t, g.IsOrgAdmin, "demote attempt must not have changed the flag")
}

func TestEscalation_JWTAdminCannotDeleteOrgAdminGroup(t *testing.T) {
	// Deleting an is_org_admin group has the same effect as demoting it —
	// every member loses admin status. Block tier-2; super-admin only.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	groups, err := srv.db.ListGroups(ctx, orgID)
	require.NoError(t, err)
	var orgAdminGroupID string
	for _, g := range groups {
		if g.IsOrgAdmin {
			orgAdminGroupID = g.ID
			break
		}
	}
	require.NotEmpty(t, orgAdminGroupID)

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGroupID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errDeleteOrgAdminGroupSuperOnly)

	g, err := srv.db.GetGroup(ctx, orgAdminGroupID)
	require.NoError(t, err)
	require.NotNil(t, g, "group must still exist after blocked delete")
}

func TestEscalation_SuperAdminCanDeleteOrgAdminGroup(t *testing.T) {
	// Super-admin (X-Admin-Token) can delete an org-admin group — the gate
	// only fires for jwt_admin. Sanity check.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	_, orgID, _ := createOrgAndAdminUser(t, srv)
	groups, err := srv.db.ListGroups(ctx, orgID)
	require.NoError(t, err)
	var orgAdminGroupID string
	for _, g := range groups {
		if g.IsOrgAdmin {
			orgAdminGroupID = g.ID
			break
		}
	}
	require.NotEmpty(t, orgAdminGroupID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGroupID, nil)
	req.Header.Set("X-Admin-Token", "secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: createUserMembership / deleteUserMembership cross-org scoping (RD-917 §3)
// ---------------------------------------------------------------------------

func TestMembership_JWTAdminCannotAddUserToForeignOrgGroup(t *testing.T) {
	// A tier-2 admin of orgA must not be able to add a user to a group
	// that lives in orgB. The membership route has no :org_id, so the
	// orgScopingMiddleware cannot enforce; the handler must.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Alice: tier-2 admin of orgA.
	aliceDID, _, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	// orgB with its own normal group and a target user.
	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))

	targetUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, targetUser))

	body := map[string]interface{}{"group_id": orgBGroup.ID}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUser.ID+"/memberships", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)

	// Verify no membership row was inserted.
	memberships, err := srv.db.ListUserMemberships(ctx, targetUser.ID)
	require.NoError(t, err)
	assert.Empty(t, memberships, "blocked add must not have inserted a row")
}

func TestMembership_JWTAdminCannotRemoveForeignOrgMembership(t *testing.T) {
	// Symmetric: tier-2 admin of orgA must not be able to delete a
	// membership row whose group lives in orgB.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, _, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))
	bob := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, bob))
	bobMembership := &rbac.UserMembership{ID: uuid.New().String(), UserID: bob.ID, GroupID: orgBGroup.ID, Source: rbac.MembershipSourceAdmin}
	require.NoError(t, srv.db.CreateMembership(ctx, bobMembership))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+bob.ID+"/memberships/"+bobMembership.ID, nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)

	// Verify membership still exists.
	got, err := srv.db.GetMembership(ctx, bobMembership.ID)
	require.NoError(t, err)
	require.NotNil(t, got, "blocked delete must not have removed the row")
}

func TestMembership_JWTAdminCanAddUserToOwnOrgGroup(t *testing.T) {
	// Positive path: tier-2 admin of orgA can add a user to a normal group
	// in orgA.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team", Name: "Team", Path: "team"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))
	bob := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, bob))

	body := map[string]interface{}{"group_id": normalGroup.ID}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+bob.ID+"/memberships", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// ---------------------------------------------------------------------------
// Test: audit log writes (RD-917 §4 — RBAC audit-log evidence completeness)
// ---------------------------------------------------------------------------

func TestAuditLog_GroupCreateRecorded(t *testing.T) {
	// Creating a group via the admin API must produce a row in
	// rbac_audit_log so Vanta / ISO 27001 access-review can trace the
	// change. Pre-fix, the rbac_audit_log table was only written for
	// user creation (internal/rbac/access.go); no group / org / membership
	// mutations were logged.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":                  "audited",
		"name":                  "Audited Group",
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	groupID := created["id"].(string)

	entries, err := srv.db.ListAuditLogs(ctx, rbac.ResourceTypeGroup, &groupID, 10, 0)
	require.NoError(t, err)
	require.Len(t, entries, 1, "exactly one audit entry expected for the create")
	entry := entries[0]
	assert.Equal(t, rbac.AuditActionCreate, entry.Action)
	assert.Equal(t, aliceDID, entry.ActorExternalID)
	assert.Equal(t, "Audited Group", entry.ResourceName)
	assert.NotNil(t, entry.NewValue)
	assert.Equal(t, true, entry.NewValue["is_org_readonly_admin"])
}
