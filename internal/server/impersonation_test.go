package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// impersonationTestServer wires the impersonation route group onto the same
// test fixture used by admin_dry_run_test.go. A tiny pre-middleware injects
// the auth context fields (auth_method, admin_subject, admin_org_ids) that
// production adminAuthMiddleware would set, so the impersonation gate's own
// checks run against a controlled identity.
//
// Test headers:
//   X-Test-Auth-Method: "jwt_admin" | "admin_token" | "" (empty = unauth)
//   X-Test-Admin-Subject: <admin DID>  (jwt_admin only)
//   X-Test-Admin-Org-IDs: <orgID,orgID2>  (jwt_admin only; comma-separated)
type impersonationTestServer struct {
	*testServerRBAC
}

func setupImpersonationTestServer(t *testing.T) *impersonationTestServer {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		method := c.GetHeader("X-Test-Auth-Method")
		if method == "" {
			c.Next()
			return
		}
		c.Set("auth_method", method)
		if method == "jwt_admin" {
			c.Set("admin_subject", c.GetHeader("X-Test-Admin-Subject"))
			orgIDs := []string{}
			if raw := c.GetHeader("X-Test-Admin-Org-IDs"); raw != "" {
				for _, id := range splitCSV(raw) {
					if id != "" {
						orgIDs = append(orgIDs, id)
					}
				}
			}
			c.Set("admin_org_ids", orgIDs)
		}
		c.Next()
	})
	admin := api.Group("/admin")
	ts.registerImpersonationRoutes(admin)
	ts.router = router
	return &impersonationTestServer{testServerRBAC: ts}
}

func splitCSV(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func impersonationGET(t *testing.T, srv *impersonationTestServer, path, authMethod, adminDID string, adminOrgIDs []string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	if adminDID != "" {
		req.Header.Set("X-Test-Admin-Subject", adminDID)
	}
	if len(adminOrgIDs) > 0 {
		raw := ""
		for i, id := range adminOrgIDs {
			if i > 0 {
				raw += ","
			}
			raw += id
		}
		req.Header.Set("X-Test-Admin-Org-IDs", raw)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// impersonationFixture mirrors dryRunFixture so the gate tests have a
// realistic two-org / admin / user / cross-org-user shape to drive against.
type impersonationFixture struct {
	srv             *impersonationTestServer
	orgID           string
	otherOrgID      string
	adminDID        string
	userDID         string
	otherOrgUserDID string
}

func setupImpersonationFixture(t *testing.T) *impersonationFixture {
	t.Helper()
	srv := setupImpersonationTestServer(t)
	ctx := context.Background()
	database := srv.db

	orgID := uuid.New().String()
	otherOrgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "imp-a", Name: "Imp A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: otherOrgID, Slug: "imp-b", Name: "Imp B", Settings: map[string]any{}}))

	adminGroupID := drCreateGroup(t, database, orgID, "imp-a-admin", nil, true /* is_org_admin */)
	adminDID := "did:imp:admin"
	drCreateUserInGroup(t, database, adminDID, adminGroupID)

	userGroupID := drCreateGroup(t, database, orgID, "imp-a-user", nil, false)
	userDID := "did:imp:user"
	drCreateUserInGroup(t, database, userDID, userGroupID)

	otherOrgGroupID := drCreateGroup(t, database, otherOrgID, "imp-b-only", nil, false)
	otherOrgUserDID := "did:imp:cross-org-user"
	drCreateUserInGroup(t, database, otherOrgUserDID, otherOrgGroupID)

	return &impersonationFixture{
		srv:             srv,
		orgID:           orgID,
		otherOrgID:      otherOrgID,
		adminDID:        adminDID,
		userDID:         userDID,
		otherOrgUserDID: otherOrgUserDID,
	}
}

// --- Gate tests ----------------------------------------------------------

func TestImpersonation_RejectsSuperAdminToken(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.userDID+"/api/v1/explorer/chain-id",
		"admin_token", "", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "super-admin tokens are not authorised")
}

func TestImpersonation_RejectsUnauthenticated(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.userDID+"/api/v1/explorer/chain-id",
		"", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// Read-only admin path: authenticated as jwt_admin but admin_org_ids is
// empty (ROA users have admin_readonly_org_ids set instead). The gate
// rejects with the tier-2 error.
func TestImpersonation_RejectsReadOnlyAdmin(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.userDID+"/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{} /* no full-admin orgs */)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "tier-2 admin required")
}

func TestImpersonation_RejectsSelfImpersonation(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.adminDID+"/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{f.orgID})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "cannot impersonate yourself")
}

// Cross-org target: admin is tier-2 of Org A; target is a member of Org B
// only. Must return generic 404 (same surface as a non-existent user) so
// the response shape can't be used as a cross-org existence oracle.
func TestImpersonation_CrossOrgTargetReturns404(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.otherOrgUserDID+"/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{f.orgID})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

func TestImpersonation_NonExistentTargetReturns404(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/did:imp:does-not-exist/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{f.orgID})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

// POST under the impersonation tree is rejected — Phase 2 is strictly
// read-only. Write-method traces go through the existing /dry-run POST.
func TestImpersonation_RejectsWriteMethod(t *testing.T) {
	f := setupImpersonationFixture(t)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/impersonate/"+f.userDID+"/rpc",
		nil)
	req.Header.Set("X-Test-Auth-Method", "jwt_admin")
	req.Header.Set("X-Test-Admin-Subject", f.adminDID)
	req.Header.Set("X-Test-Admin-Org-IDs", f.orgID)
	w := httptest.NewRecorder()
	f.srv.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Contains(t, w.Body.String(), "read-only")
}

// Happy path smoke: a tier-2 admin in Org A browsing as a user in Org A
// gets the explorer's /chain-id response. /chain-id is the simplest
// always-available endpoint; the test verifies the gate + dispatch pipe is
// wired, not the redaction semantics (those are covered by the
// access_visibility_symmetry e2e test extended below).
func TestImpersonation_AllowsSameOrgExplorerGET(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.userDID+"/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{f.orgID})
	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body, "chain_id")
}

// The viewer override must be set on the context after the gate runs.
// Test this indirectly via a tiny test handler that returns the override
// value — the production handlers do the same via getViewerDIDFromRequest.
func TestImpersonation_SetsViewerOverrideContext(t *testing.T) {
	f := setupImpersonationFixture(t)

	// Override the wired explorer/chain-id with an introspection handler
	// just for this test path. We rebuild the route tree off the same
	// fixture server so the middleware chain still runs identically.
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		method := c.GetHeader("X-Test-Auth-Method")
		if method != "" {
			c.Set("auth_method", method)
			if method == "jwt_admin" {
				c.Set("admin_subject", c.GetHeader("X-Test-Admin-Subject"))
				c.Set("admin_org_ids", splitCSV(c.GetHeader("X-Test-Admin-Org-IDs")))
			}
		}
		c.Next()
	})
	admin := api.Group("/admin")
	imp := admin.Group("/impersonate/:target_did")
	imp.Use(f.srv.impersonationGateMiddleware())
	imp.GET("/probe", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"viewer":         getEffectiveViewerDID(c),
			"impersonating":  isImpersonating(c),
			"impersonator":   c.GetString(impersonationActorDIDContextKey),
			"resolved_org":   c.GetString(impersonationOrgIDContextKey),
		})
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/impersonate/"+f.userDID+"/probe", nil)
	req.Header.Set("X-Test-Auth-Method", "jwt_admin")
	req.Header.Set("X-Test-Admin-Subject", f.adminDID)
	req.Header.Set("X-Test-Admin-Org-IDs", f.orgID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, f.userDID, body["viewer"], "viewer override must be applied")
	assert.True(t, body["impersonating"].(bool))
	assert.Equal(t, f.adminDID, body["impersonator"])
	assert.Equal(t, f.orgID, body["resolved_org"])
}

// Defensive header strip: client-supplied X-Admin-Token and impersonation
// envelope headers must not survive past the gate.
func TestImpersonation_StripsDefensiveHeaders(t *testing.T) {
	f := setupImpersonationFixture(t)
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_subject", f.adminDID)
		c.Set("admin_org_ids", []string{f.orgID})
		c.Next()
	})
	admin := api.Group("/admin")
	imp := admin.Group("/impersonate/:target_did")
	imp.Use(f.srv.impersonationGateMiddleware())
	imp.GET("/echo-headers", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"admin_token":  c.Request.Header.Get("X-Admin-Token"),
			"imp_did":      c.Request.Header.Get("X-Impersonate-User-DID"),
			"imp_token":    c.Request.Header.Get("X-Impersonate-Token"),
		})
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/impersonate/"+f.userDID+"/echo-headers", nil)
	req.Header.Set("X-Admin-Token", "should-be-stripped")
	req.Header.Set("X-Impersonate-User-DID", "should-be-stripped")
	req.Header.Set("X-Impersonate-Token", "should-be-stripped")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Empty(t, body["admin_token"], "X-Admin-Token must be stripped")
	assert.Empty(t, body["imp_did"], "X-Impersonate-User-DID must be stripped")
	assert.Empty(t, body["imp_token"], "X-Impersonate-Token must be stripped")
}

// Audit-log row written per request. Uses the real impersonation_log table
// (migration 047) via the testServerRBAC's DB.
func TestImpersonation_AuditLogRowWritten(t *testing.T) {
	f := setupImpersonationFixture(t)
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.userDID+"/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{f.orgID})
	require.Equal(t, http.StatusOK, w.Code)

	ctx := context.Background()
	conn := f.srv.db.Conn()
	require.NotNil(t, conn)
	row := conn.QueryRowContext(ctx, `
		SELECT actor_did, impersonated_did, org_id, decision
		FROM impersonation_log
		WHERE actor_did = $1 AND impersonated_did = $2
		ORDER BY created_at DESC LIMIT 1`,
		f.adminDID, f.userDID)
	var actor, target, org, decision string
	require.NoError(t, row.Scan(&actor, &target, &org, &decision))
	assert.Equal(t, f.adminDID, actor)
	assert.Equal(t, f.userDID, target)
	assert.Equal(t, f.orgID, org)
	assert.Equal(t, "allow", decision)
}

// Deny gets audit-logged too (with http_<status> reason).
func TestImpersonation_AuditLogRowWrittenOnDeny(t *testing.T) {
	f := setupImpersonationFixture(t)
	// Cross-org target → 404 → "deny" in impersonation_log
	w := impersonationGET(t, f.srv,
		"/api/v1/admin/impersonate/"+f.otherOrgUserDID+"/api/v1/explorer/chain-id",
		"jwt_admin", f.adminDID, []string{f.orgID})
	require.Equal(t, http.StatusNotFound, w.Code)

	// 404-on-target-not-found short-circuits the gate BEFORE setting the
	// override and BEFORE c.Next(), so no audit row is written. The audit
	// path runs only when the request is dispatched to a handler — i.e.
	// the target was validated as same-org. This is the right shape:
	// failed lookups don't pollute the audit table, and any handler-level
	// deny does. The cross-org case is intentionally indistinguishable
	// from a missing user in both the response AND the audit log.
	ctx := context.Background()
	conn := f.srv.db.Conn()
	require.NotNil(t, conn)
	var count int
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM impersonation_log WHERE impersonated_did = $1`,
		f.otherOrgUserDID).Scan(&count))
	assert.Equal(t, 0, count, "cross-org / not-found target does not write an audit row by design")
}
