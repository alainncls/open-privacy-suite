package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1107: the super-admin token (X-Admin-Token) is a platform / bootstrap /
// fleet credential. It must NOT perform per-org tenant management — regular
// groups, group access, memberships into regular groups, contracts, and
// grants are the tier-2 org admin's job. It STILL manages the admin tier
// (is_org_admin groups, org lifecycle) so bootstrap and org-admin minting work.
//
// These tests pin both halves on the RBAC routes registered by
// registerRBACRoutes. (Per-org compliance gating uses the same
// denySuperAdminOrgScoped helper and is exercised end-to-end against the live
// stack; its routes are not wired into setupTieredAdminTestServer.)

// superReq issues an admin request with the super-admin token.
func superReq(t *testing.T, router http.Handler, method, url string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, url, r)
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRD1107_SuperAdminBlockedFromRegularInOrgMutations(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// A user we can attempt to add to a regular group by UUID.
	user := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	const wantMsg = errSuperAdminNoTenantMgmt

	t.Run("create regular group", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups",
			map[string]any{"slug": "team-x", "name": "Team X"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("set access on regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+gid+"/access",
			map[string]any{"allowed_methods": []string{"eth_call"}, "claims": []string{}})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("delete regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+gid, nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("batch-delete including a regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups/batch-delete",
			map[string]any{"group_ids": []string{gid}})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("create contract", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/contracts",
			map[string]any{"address": "0x1111111111111111111111111111111111111111", "name": "Tok"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("create grant", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost,
			"/api/v1/admin/orgs/"+orgID+"/contracts/0x1111111111111111111111111111111111111111/grants",
			map[string]any{"group_id": gid})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("onboard-by-did into regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
			map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("add membership by uuid into regular group", func(t *testing.T) {
		_, gid := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/users/"+user.ID+"/memberships",
			map[string]any{"group_id": gid})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})
}

func TestRD1107_SuperAdminKeepsPlatformAndAdminTierOps(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	t.Run("create org", func(t *testing.T) {
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs",
			map[string]any{"slug": "plat-" + uuid.New().String()[:8], "name": "Platform Org"})
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("create is_org_admin group (mint org admin)", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups",
			map[string]any{"slug": "admins", "name": "Admins", "is_org_admin": true})
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("set access on is_org_admin group", func(t *testing.T) {
		orgID, gid := createOrgWithOrgAdminGroup(t, srv)
		w := superReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+gid+"/access",
			map[string]any{"allowed_methods": []string{"eth_call"}, "claims": []string{}})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("onboard-by-did into is_org_admin group", func(t *testing.T) {
		orgID, gid := createOrgWithOrgAdminGroup(t, srv)
		w := superReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
			map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("delete org", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := superReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRD1107_Tier2OrgAdminStillManagesRegularGroups(t *testing.T) {
	// Sanity: the change must not break the tier-2 path it hands the work to.
	srv, router := setupTieredAdminTestServer(t, "secret")
	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"slug": "team-y", "name": "Team Y"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}
