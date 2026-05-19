// RD-944 — pin the admin-org fallback on the disclosure list endpoints.
//
// Pre-fix `listDisclosureRequests` defaulted to the system default org
// (`00000000-...001`) when no `org_id` query param was supplied. For any
// tier-2 admin of a real org the system default org isn't in
// admin_org_ids, so requireTargetInScope always 403'd — breaking the
// dashboard Disclosure tab for every prod tier-2 admin.
//
// `listDisclosureGrants` already had the right behaviour (default to
// caller's first full-admin org); the fix mirrored that in
// listDisclosureRequests so the two parallel requests fired by the
// frontend now succeed symmetrically.
//
// This test exercises the four acceptance criteria from the RD-944
// issue body against a real testcontainer Postgres, simulating
// jwt_admin context via a small middleware that sets the same gin keys
// adminAuthMiddleware would in production.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
)

// fakeAdminAuth sets the same gin context keys adminAuthMiddleware
// would after a real JWT-admin token validation. Used to drive the
// scoping branches in disclosure list handlers without standing up the
// full JWT+claims plumbing.
func fakeAdminAuth(authMethod string, fullAdminOrgIDs, readonlyAdminOrgIDs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authMethod != "" {
			c.Set("auth_method", authMethod)
		}
		if fullAdminOrgIDs != nil {
			c.Set("admin_org_ids", fullAdminOrgIDs)
		}
		if readonlyAdminOrgIDs != nil {
			c.Set("admin_readonly_org_ids", readonlyAdminOrgIDs)
		}
		c.Next()
	}
}

func setupDisclosureRouterWithAuth(srv *Server, auth gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	if auth != nil {
		api.Use(auth)
	}
	srv.registerDisclosureRoutes(api)
	return router
}

func seedRequest(t *testing.T, database *db.DB, orgID string) string {
	t.Helper()
	targetUserID := uuid.New().String()
	ctx := context.Background()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, "did:test:rd944-"+uuid.New().String()[:8])
	require.NoError(t, err)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{},
		Reason:       "rd-944 seed",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	require.NoError(t, database.CreateRequest(ctx, req))
	return req.ID
}

// AC #1 — single-org tier-2 admin opens disclosure tab without org_id → list loads (no 403).
func TestRD944_ListRequests_JWTAdmin_NoOrgID_PicksOwnOrg(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-orgA")
	_ = seedRequest(t, database, orgA) // seed one request so we can confirm the right org was picked

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "tier-2 admin of orgA must see disclosure list scoped to orgA; got body=%s", w.Body.String())
	var resp disclosure.DisclosureListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Requests, 1, "should see the seeded request in caller's own org")
}

// AC #2 — multi-org tier-2 admin without org_id silently picks one of their orgs
// (matches listDisclosureGrants' pre-existing list[0] behaviour). Frontend should
// pass explicit org_id for multi-org admins; tested below.
func TestRD944_ListRequests_JWTAdmin_MultiOrg_NoOrgID_PicksFirst(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-multiA")
	orgB := createTestOrgForHandler(t, database, "rd944-multiB")
	_ = seedRequest(t, database, orgA)
	_ = seedRequest(t, database, orgB)

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA, orgB}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "multi-org admin without org_id should NOT 403 — default to first full-admin org")
	var resp disclosure.DisclosureListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// Should see exactly one request (from list[0] = orgA), not both — this
	// is the same shape as listDisclosureGrants today.
	assert.Len(t, resp.Requests, 1, "multi-org admin default picks the first admin org only")
}

// AC #2 continued — explicit org_id allows multi-org admin to choose their other org.
func TestRD944_ListRequests_JWTAdmin_MultiOrg_ExplicitOrgID_Works(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-explicit-A")
	orgB := createTestOrgForHandler(t, database, "rd944-explicit-B")
	_ = seedRequest(t, database, orgA)
	_ = seedRequest(t, database, orgB)

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA, orgB}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests?org_id="+orgB, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp disclosure.DisclosureListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Requests, 1, "explicit org_id should scope to that org")
}

// AC #3 — Audit C3 preserved: cross-org probe still 403s.
// Alice admins orgA, tries to query disclosure requests for orgB she
// has no admin role in. Must 403, regardless of whether orgB exists.
func TestRD944_ListRequests_CrossOrgProbe_StillBlocked(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-c3-A")
	orgB := createTestOrgForHandler(t, database, "rd944-c3-B")

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests?org_id="+orgB, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusForbidden, w.Code, "Audit C3 must still fire: tier-2 admin of orgA cannot query orgB's disclosure list. body=%s", w.Body.String())
}

// AC #4 — super-admin (no auth_method set, mirrors X-Admin-Token in
// real adminAuthMiddleware path) without org_id falls back to system
// default org. Pre-fix behaviour preserved for admin scripts.
func TestRD944_ListRequests_SuperAdmin_NoOrgID_UsesSystemDefault(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	// No fakeAdminAuth installed — auth_method stays empty, matching
	// the dev/super-admin bypass path in requireTargetInScope.
	router := setupDisclosureRouterWithAuth(srv, nil)

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "super-admin / dev caller without org_id must still succeed (falls back to system default). body=%s", w.Body.String())
}

// AC #5 — RO-admin only (no full admin orgs) without org_id is denied
// with a clear 400, not silently scoped to a random org.
func TestRD944_ListRequests_ROAdminOnly_NoOrgID_400(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-ro-only")
	_ = orgA

	// admin_org_ids = empty slice (no full-admin orgs), readonly_admin_org_ids = [orgA]
	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{}, []string{orgA}))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusBadRequest, w.Code, "RO-admin only without org_id must get 400, not silent system-default fallback. body=%s", w.Body.String())
}
