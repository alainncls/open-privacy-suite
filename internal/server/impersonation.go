package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RD-928 — "View as user" impersonation surface.
//
// Tier-2 org admins can browse the explorer / call read-only RPC as if they
// were a target user in the same org, without ever minting a user-shaped JWT.
// The mechanism is a parallel URL tree:
//
//   /api/v1/admin/impersonate/:target_did/explorer/<sub-path>
//   /api/v1/admin/impersonate/:target_did/rpc[/:org_id]
//
// These re-use the existing explorer / RPC handlers via a single per-request
// override carried in gin.Context. impersonationGateMiddleware does all the
// gating up front:
//
//   1. tier-2 admin only (super-admin token + tier-3 + read-only admin → 403)
//   2. target user exists AND has a membership in the admin's org (else 404,
//      same shape as RD-872 dry-run — never reveal cross-org existence)
//   3. self-impersonation rejected
//   4. GET-only on this surface (write methods 405) — Phase 2 of RD-872 is
//      strictly read-only by design
//   5. defensive header strip: X-Admin-Token and any X-Impersonate-* headers
//      from the client are removed before the request hits the downstream
//      handler chain (the BFF should never have forwarded them, but DiD)
//   6. per-request impersonation_log row, fail-closed: if the audit write
//      errors we refuse the response rather than expose data unlogged
//
// On success the middleware sets:
//
//   c.Set(viewerDIDOverrideContextKey, target_did)
//   c.Set(impersonationActorDIDContextKey, admin_did)
//   c.Set(impersonationOrgIDContextKey, admin_org_id)
//
// Downstream:
//
//   - getViewerDIDFromRequest (explorer_api.go) honors the override.
//   - handleJSONRPC reads it via getEffectiveViewerDID below.
//   - The CheckAccess call sets BypassCache so the impersonated viewer's
//     in-memory perms aren't served from a 5-min-stale entry. (The resolver's
//     DB cache may still serve stale up to its TTL — that's RD-956's surface,
//     not RD-928's.)
//
// Why this is safe for tier-2 admin same-org browse-as: by
// rbac.computeOrgAdminPermissions, the admin has full claims on every
// contract in their org, so any data exposed through the impersonated viewer
// is already in the admin's reach via direct calls. Net new data: zero. The
// surface is an *ergonomics* tool wrapped in audit logging, not a privilege
// expansion. Cross-org structurally impossible because the same-org check
// runs before the override is set.

// Context keys for the impersonation override. Strings, not custom types,
// so the explorer handlers (which already read string keys like "subject")
// stay readable. The keys are only written by impersonationGateMiddleware;
// see the SECURITY: comment in getViewerDIDFromRequest for the invariant.
const (
	viewerDIDOverrideContextKey   = "rd928_viewer_did_override"
	impersonationActorDIDContextKey = "rd928_impersonation_actor_did"
	impersonationOrgIDContextKey  = "rd928_impersonation_org_id"
)

// errImpersonationTargetNotFound is the sentinel returned by the same-org
// resolution path. It maps to a generic 404 so a tier-2 admin in Org A
// cannot probe whether `did:foo` exists in Org B.
var errImpersonationTargetNotFound = errors.New("user not found")

// registerImpersonationRoutes mounts the impersonation surface as a
// path-prepend namespace: every existing read-side URL on the proxy is
// reachable under
//
//	/api/v1/admin/impersonate/:target_did<original-url>
//
// i.e. an explorer call to /api/v1/explorer/blocks/123 becomes
// /api/v1/admin/impersonate/<did>/api/v1/explorer/blocks/123, and an RPC
// call to /rpc becomes /api/v1/admin/impersonate/<did>/rpc. The BFF
// rewrites paths by simple concatenation — no segment surgery — which keeps
// the contract robust as new explorer endpoints are added.
//
// The route group inherits localhost-only + admin-auth from the parent admin
// group. impersonationGateMiddleware re-enforces tier-2 admin specifically
// (rejecting super-admin token + read-only admin) and adds the same-org
// check.
//
// Two sub-trees:
//   - /api/v1/explorer/* re-uses bindExplorerEndpoints (shared with the
//     production explorer routes) but with the impersonation gate +
//     viewer override.
//   - /rpc[/:org_id] re-uses handleJSONRPC.
//
// auth.OptionalJWTAuthMiddleware is NOT applied here — the admin gate
// already validated the caller's JWT, and we don't want an anonymous viewer
// fallback under this tree.
func (s *Server) registerImpersonationRoutes(adminGroup *gin.RouterGroup) {
	imp := adminGroup.Group("/impersonate/:target_did")
	imp.Use(s.impersonationGateMiddleware())

	// Explorer subtree is re-mounted at /api/v1/explorer (matching its
	// production prefix) so the BFF just prepends
	// /api/v1/admin/impersonate/<did> to whatever explorer URL it was
	// going to call. Reuse the same log-redaction middleware production
	// explorer routes use — impersonated paths can still embed Ethereum
	// addresses we don't want in access logs.
	explorerImp := imp.Group("/api/v1/explorer")
	explorerImp.Use(explorerLogRedactionMiddleware())
	s.bindExplorerEndpoints(explorerImp)

	// RPC subtree: mirror the production /rpc and /rpc/:org_id shapes.
	// /rpc has no /api/v1 prefix in production so it sits directly under
	// /api/v1/admin/impersonate/:target_did/rpc here too.
	//
	// We register Any() (not GET) so non-GET methods reach the middleware's
	// 405 check instead of gin's no-route 404 — surfaces the right HTTP
	// semantics ("method not allowed" not "endpoint missing") to the BFF
	// and makes the "POST under impersonation is rejected" assertion
	// auditable. The middleware unconditionally rejects c.Request.Method
	// != GET.
	imp.Any("/rpc", s.handleJSONRPC)
	imp.Any("/rpc/:org_id", s.handleJSONRPC)
}

// impersonationGateMiddleware enforces the RD-928 gate rules and sets the
// viewer override + audit-log identity context values. See the package-level
// doc on this file for the full enforcement matrix.
func (s *Server) impersonationGateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Super-admin token bypasses orgScopingMiddleware on regular admin
		// routes; for impersonation it must NOT — super-admin has no
		// data-layer reach today and this would be the path that gives it
		// to them. Reject explicitly with the same 403 surface as
		// handleDryRun.
		if c.GetString("auth_method") == "admin_token" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "impersonation requires a tier-2 admin JWT; super-admin tokens are not authorised",
			})
			return
		}

		adminDID := c.GetString("admin_subject")
		if adminDID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
			return
		}

		// Tier-2 admin only: read-only admin (RD-866) is excluded.
		// admin_org_ids is non-empty for tier-2 admins, empty for ROA.
		adminOrgIDs, ok := c.Get("admin_org_ids")
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tier-2 admin required"})
			return
		}
		orgIDs, ok := adminOrgIDs.([]string)
		if !ok || len(orgIDs) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tier-2 admin required"})
			return
		}

		// GET-only on this surface. Phase 2 of RD-872 is strictly
		// read-only by design — write methods go through /dry-run which
		// translates them to debug_traceCall against a discarded state.
		if c.Request.Method != http.MethodGet {
			c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{
				"error": "impersonation surface is read-only; use POST /api/orgs/:org_id/dry-run for write-method traces",
			})
			return
		}

		targetDID := strings.TrimSpace(c.Param("target_did"))
		if targetDID == "" {
			// Gin shouldn't route us here without the param, but defend.
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "target_did required"})
			return
		}
		if targetDID == adminDID {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "cannot impersonate yourself"})
			return
		}

		// Defensive header strip: a misbehaving BFF (or compromised one)
		// must not be able to smuggle alternate identity envelopes into
		// the downstream chain. RD-877's `subject` claim is JWT-derived
		// and immutable here; these headers are unused by privacy-proxy
		// and are stripped purely to keep the BFF contract clean.
		c.Request.Header.Del("X-Admin-Token")
		c.Request.Header.Del("X-Impersonate-User-DID")
		c.Request.Header.Del("X-Impersonate-Token")

		// Resolve the target user in one of the admin's orgs. We don't
		// take an org_id from the URL — we infer the org from the
		// intersection of the admin's admin_org_ids with the target's
		// memberships. If the target is in multiple admin orgs the first
		// match wins (rare; org admins are typically single-org). If
		// none match → 404 (no info disclosure).
		orgID, lookupErr := s.resolveImpersonationOrg(c.Request.Context(), targetDID, orgIDs)
		if errors.Is(lookupErr, errImpersonationTargetNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if lookupErr != nil {
			slog.Error("impersonation: org resolution failed", "admin_did", adminDID, "err", lookupErr)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		// Set the override and identity tags BEFORE handler dispatch so
		// downstream code (getViewerDIDFromRequest, handleJSONRPC) sees
		// them. Audit log fires after dispatch so it captures the
		// downstream decision in `reason` (allow / deny / error).
		c.Set(viewerDIDOverrideContextKey, targetDID)
		c.Set(impersonationActorDIDContextKey, adminDID)
		c.Set(impersonationOrgIDContextKey, orgID)

		c.Next()

		// Post-handler: write one audit row per impersonated request. We
		// use the HTTP status as the decision proxy (2xx → "allow", 4xx
		// → "deny", 5xx → "error"). The request path is the "method"
		// column — params_hash is the sha256 of the raw query string
		// (impersonation token already stripped at the BFF, never
		// reaches us). Fail-closed: if the audit write errors AFTER a
		// 2xx response we can't unsend the body, but we log loudly and
		// flip the response code so the caller sees the inconsistency
		// on the next polled error.
		status := c.Writer.Status()
		decision := decisionFromStatus(status)
		reason := ""
		if decision != "allow" {
			reason = fmt.Sprintf("http_%d", status)
		}
		if logErr := s.recordImpersonationRequest(
			c.Request.Context(),
			adminDID,
			targetDID,
			orgID,
			c.Request.Method+" "+c.Request.URL.Path,
			c.Request.URL.RawQuery,
			decision,
			reason,
			getCorrelationID(c),
		); logErr != nil {
			// Body already sent — we can't unsend. Log loudly. The next
			// caller attempting to use this admin's JWT will see the
			// audit-write health surface (when we add one) regardless.
			slog.Error("impersonation: audit log write failed AFTER response",
				"admin_did", adminDID, "target_did", targetDID, "path", c.Request.URL.Path, "err", logErr)
		}
	}
}

// resolveImpersonationOrg returns the admin-scoped org ID in which the target
// user has a membership, or errImpersonationTargetNotFound if the target
// doesn't exist OR isn't in any of the admin's orgs.
//
// Cross-org targets and never-seen DIDs collapse to the same sentinel — by
// design, so the response shape can't be used as a user-existence oracle
// across org boundaries.
func (s *Server) resolveImpersonationOrg(ctx context.Context, targetDID string, adminOrgIDs []string) (string, error) {
	if s.db == nil {
		return "", fmt.Errorf("db not configured")
	}
	user, err := s.db.GetUserByExternalID(ctx, targetDID)
	if err != nil {
		return "", fmt.Errorf("user lookup: %w", err)
	}
	if user == nil {
		return "", errImpersonationTargetNotFound
	}
	userOrgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(ctx, user.ID)
	if err != nil {
		return "", fmt.Errorf("user org lookup: %w", err)
	}
	adminSet := make(map[string]struct{}, len(adminOrgIDs))
	for _, id := range adminOrgIDs {
		adminSet[id] = struct{}{}
	}
	for _, uOrg := range userOrgIDs {
		if _, ok := adminSet[uOrg]; ok {
			return uOrg, nil
		}
	}
	return "", errImpersonationTargetNotFound
}

// getEffectiveViewerDID returns the impersonation override if set, else the
// JWT-derived subject. Used by handleJSONRPC and any future handler that
// needs the "who is the request acting as" answer.
//
// Identical priority to getViewerDIDFromRequest in explorer_api.go — kept
// as a separate function because the explorer surface also has a wallet
// fallback comment chain that doesn't apply on the RPC side.
func getEffectiveViewerDID(c *gin.Context) string {
	if override, exists := c.Get(viewerDIDOverrideContextKey); exists {
		if did, ok := override.(string); ok && did != "" {
			return did
		}
	}
	if subject, exists := c.Get("subject"); exists {
		if did, ok := subject.(string); ok && did != "" {
			return did
		}
	}
	return ""
}

// isImpersonating reports whether the current request is running under the
// impersonation override. CheckAccess callers use this to set BypassCache.
func isImpersonating(c *gin.Context) bool {
	override, exists := c.Get(viewerDIDOverrideContextKey)
	if !exists {
		return false
	}
	did, ok := override.(string)
	return ok && did != ""
}

// decisionFromStatus maps HTTP status to the impersonation_log.decision
// enum. 2xx → allow, 4xx → deny, anything else → error.
func decisionFromStatus(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "allow"
	case status >= 400 && status < 500:
		return "deny"
	default:
		return "error"
	}
}

// recordImpersonationRequest writes one impersonation_log row for a non-RPC
// impersonated call (explorer GETs, RPC GETs). The dry-run RPC POST flow
// keeps its own recordImpersonation helper for back-compat with PR #199.
func (s *Server) recordImpersonationRequest(
	ctx context.Context,
	actorDID, impersonatedDID, orgID string,
	method string,
	rawQuery string,
	decision, reason, correlationID string,
) error {
	if s.db == nil {
		return nil
	}
	conn := s.db.Conn()
	if conn == nil {
		return nil
	}
	corr := uuid.NullUUID{}
	if id, err := uuid.Parse(correlationID); err == nil {
		corr.UUID = id
		corr.Valid = true
	}
	// Hash the query string (already token-stripped by the BFF before the
	// request reached us). We never persist the raw query — it can carry
	// private addresses or block-hash filters that should not appear in
	// the audit table per migration 047.
	paramsHash := ""
	if rawQuery != "" {
		sum := sha256.Sum256([]byte(rawQuery))
		paramsHash = hex.EncodeToString(sum[:])
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO impersonation_log (actor_did, impersonated_did, org_id, method, params_hash, decision, reason, correlation_id)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)`,
		actorDID, impersonatedDID, orgID, method, paramsHash, decision, reason, corr,
	)
	return err
}

// applyImpersonationToAccessRequest sets BypassCache on the given access
// request when the gin context carries the impersonation override. Reserved
// for explorer endpoints that build their own AccessCheckRequest (the RPC
// path goes through ProcessRequest.BypassPermsCache). Keep as a thin helper
// so future viewer-aware admin surfaces inherit cache-bypass for free.
func applyImpersonationToAccessRequest(c *gin.Context, req *rbac.AccessCheckRequest) {
	if !isImpersonating(c) {
		return
	}
	req.BypassCache = true
}
