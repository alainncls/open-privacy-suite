package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-968: the "org admin" role maps to several independent fields
// (groups.is_org_admin, groups.is_org_readonly_admin, group_access.claims,
// group_access.allowed_methods). These tests pin the server-side invariants that
// stop a caller from persisting a self-contradictory or silently-useless
// combination. The matching DB CHECK constraint (migration 060) is covered by
// TestOrgAdminInvariant_AdminRoleExclusiveConstraint.

// createOrgWithOrgAdminGroup creates an org plus a full org-admin group (with a
// minimal, valid group_access) and returns their IDs. Uses direct DB writes so
// the fixture is independent of the handlers under test.
func createOrgWithOrgAdminGroup(t *testing.T, srv *Server) (orgID, groupID string) {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "oa-" + uuid.New().String()[:8],
		Name: "Org-Admin Test Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "admins-" + uuid.New().String()[:8],
		Name:       "Org Admins",
		Path:       "org-admins",
		IsOrgAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	return org.ID, group.ID
}

// createOrgWithNormalGroup creates an org plus a plain (non-admin) group.
func createOrgWithNormalGroup(t *testing.T, srv *Server) (orgID, groupID string) {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "ng-" + uuid.New().String()[:8],
		Name: "Normal Group Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "normal-" + uuid.New().String()[:8],
		Name:  "Normal",
		Path:  "normal",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	return org.ID, group.ID
}

func putJSON(t *testing.T, router http.Handler, url string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(bodyBytes))
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ── Gap 2: is_org_admin XOR is_org_readonly_admin ──────────────────────────────

func TestOrgAdminInvariant_CreateRejectsBothAdminFlags(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "both-" + uuid.New().String()[:8], Name: "Both Flags Org"}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	// Super-admin so the is_org_admin tier gate is not the thing that rejects us —
	// we want to exercise the mutual-exclusion check specifically.
	body := map[string]any{
		"slug":                  "broken-admins",
		"name":                  "Broken Admins",
		"is_org_admin":          true,
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+org.ID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), errAdminRolesMutuallyExclusive)
}

func TestOrgAdminInvariant_UpdateRejectsResultingBothAdminFlags(t *testing.T) {
	// Toggling read-only on a group that is ALREADY is_org_admin must be rejected
	// on the merged result — this is the OP's "I'll demote myself to read-only"
	// path that previously produced a silently contradictory row.
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID, map[string]any{
		"is_org_readonly_admin": true,
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), errAdminRolesMutuallyExclusive)
}

func TestOrgAdminInvariant_UpdateReadonlyOnNormalGroupStillSucceeds(t *testing.T) {
	// Guard against over-broad enforcement: a normal group (is_org_admin=false)
	// can still be marked read-only admin.
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithNormalGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID, map[string]any{
		"is_org_readonly_admin": true,
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── Gap 1: claims do not apply to org-admin groups ─────────────────────────────

func TestOrgAdminInvariant_SetAccessRejectsClaimsOnOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", map[string]any{
		"allowed_methods": []string{"eth_call"},
		"claims":          []string{"admin"},
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), errOrgAdminClaimsNotApplicable)
}

func TestOrgAdminInvariant_SetAccessAllowsEmptyClaimsOnOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", map[string]any{
		"allowed_methods": []string{"eth_call"},
		"claims":          []string{},
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── Gap 3: org-admin groups must allow at least one method ──────────────────────

func TestOrgAdminInvariant_SetAccessRejectsEmptyMethodsOnOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", map[string]any{
		"allowed_methods": []string{},
		"claims":          []string{},
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), errOrgAdminMethodsRequired)
}

// ── Validator carve-out: org-admin effective claims are all-of-them ────────────

func TestOrgAdminInvariant_SetAccessAllowsDeployMethodWithoutStoredClaims(t *testing.T) {
	// debug_traceTransaction requires the deploy claim under
	// ValidateMethodsMatchClaims. On an org-admin group the resolver grants all
	// claims, so the stored-claims check must be skipped — otherwise a legitimate
	// org-admin method set would be wrongly rejected.
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", map[string]any{
		"allowed_methods": []string{"eth_call", "debug_traceTransaction"},
		"claims":          []string{},
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOrgAdminInvariant_SetAccessOnNormalGroupStillValidatesMethodClaims(t *testing.T) {
	// The carve-out above must NOT disable the validator globally: a normal group
	// listing a deploy-tier method without the deploy claim is still rejected.
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, groupID := createOrgWithNormalGroup(t, srv)

	w := putJSON(t, router, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", map[string]any{
		"allowed_methods": []string{"debug_traceTransaction"},
		"claims":          []string{},
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DB backstop: migration 060 CHECK constraint ────────────────────────────────

func TestOrgAdminInvariant_AdminRoleExclusiveConstraint(t *testing.T) {
	// Defense in depth: even a direct SQL write (bypassing the handlers) cannot
	// produce a group that is both a full org admin and a read-only admin.
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()
	_, groupID := createOrgWithOrgAdminGroup(t, srv) // is_org_admin = true

	_, err := srv.db.Conn().ExecContext(ctx,
		`UPDATE groups SET is_org_readonly_admin = true WHERE id = $1`, groupID)

	require.Error(t, err, "DB CHECK constraint must reject both admin flags on one group")
	assert.Contains(t, err.Error(), "groups_admin_role_exclusive")
}
