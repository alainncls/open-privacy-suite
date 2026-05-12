package server

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
)

// errTargetForeignOrg is the opaque deny string used by every admin
// handler that loads a global-by-ID resource (user, group, contract,
// session, sanction, azure tenant, …) and rejects callers whose
// admin_org_ids does not include the resource's parent org.
//
// The string intentionally matches the "not found" case so a tier-2
// admin cannot distinguish "exists in another org" from "does not
// exist" — the same shape RD-916 / RD-917 / PR #207 established for
// the membership and group-list handlers.
const errTargetForeignOrg = "access denied to target resource"

// requireTargetInScope is the canonical cross-org gate for handlers
// whose route does NOT carry :org_id (the resource is identified by a
// global ID like :user_id, :membership_id, :session_id, …) OR whose
// :org_id path parameter is not sufficient to guarantee the loaded
// resource actually lives in that org (the handler must re-verify).
//
// Returns true if the caller may proceed. Returns false (and writes a
// 403) when the caller is a JWT admin whose admin_org_ids does not
// contain targetOrgID. Super-admin (X-Admin-Token) and dev-mode
// callers always proceed.
//
// Read-only admins ARE accepted here — this helper only enforces the
// org-scope dimension. Mutation-vs-read enforcement lives in
// orgScopingMiddleware (for routes with :org_id) or in the handler's
// own role check (use requireFullAdminInScope for that combination).
func requireTargetInScope(c *gin.Context, targetOrgID string) bool {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		// admin_token (super-admin) or empty (dev mode) — bypass.
		return true
	}
	if targetOrgID == "" {
		// A truly global resource (system setting, anonymous group,
		// etc.) reaching this helper means the caller intended super-
		// admin only. JWT admins are denied.
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return false
	}
	// Allow if the org is in either full-admin or read-only-admin scope.
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok && slices.Contains(list, targetOrgID) {
			return true
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok && slices.Contains(list, targetOrgID) {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
	return false
}

// requireFullAdminInScope is the mutating-handler companion to
// requireTargetInScope: same org-scope check, but also rejects
// read-only admins. Use this in any non-GET handler whose route does
// not carry :org_id (orgScopingMiddleware would normally apply the
// role check via the path param; without :org_id, the handler is
// responsible).
//
// Returns true if the caller is super-admin / dev or a full
// (is_org_admin) admin of targetOrgID. Returns false with 403 in
// every other case.
func requireFullAdminInScope(c *gin.Context, targetOrgID string) bool {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		return true
	}
	if targetOrgID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return false
	}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok && slices.Contains(list, targetOrgID) {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
	return false
}

// requireSuperAdmin rejects every caller except X-Admin-Token /
// dev mode. Use for genuinely global mutations (Azure tenant CRUD,
// system base-currency switch, global sanction add, …).
func requireSuperAdmin(c *gin.Context) bool {
	authMethod := c.GetString("auth_method")
	if authMethod == "admin_token" || authMethod == "" {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "super-admin required"})
	return false
}
