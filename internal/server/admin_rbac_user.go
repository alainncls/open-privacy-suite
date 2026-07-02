package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// User handlers

// errMembershipForeignOrg is returned when a JWT-authenticated org admin
// tries to add or remove a membership whose target group lives in an org
// they do not full-admin. The deny string is intentionally generic so it
// also covers the "group not found" case from the same code path —
// disclosing "this group exists but is in another org" would itself be a
// cross-org leak (see RD-916).
const errMembershipForeignOrg = "access denied to target group"

// userListItem extends rbac.User with the user's group memberships for the
// list response. Memberships are scoped to the caller's accessible orgs
// for non-super-admin callers (cross-org isolation).
type userListItem struct {
	*rbac.User
	Groups []rbac.UserGroupMembership `json:"groups"`
}

// requireUserInCallerScope ensures the target user shares at least one
// org with the caller's admin scope (full or read-only). Returns true
// if the caller may proceed; writes a 403 otherwise.
//
// Super-admin (X-Admin-Token) and dev-mode callers bypass.
//
// The error string is intentionally identical to errTargetForeignOrg
// so a tier-2 admin cannot distinguish "user exists in another org"
// from "user does not exist" via the response.
//
// Caller must pass the user's memberships' org IDs (resolved via
// GetUserOrgIDs). Empty intersection = denied.
func (s *Server) requireUserInCallerScope(c *gin.Context, userID string) bool {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		return true
	}
	userOrgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(c.Request.Context(), userID)
	if err != nil {
		slog.Error("scope check: GetUserOrgIDs failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "scope check failed"})
		return false
	}
	allowed := map[string]struct{}{}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				allowed[id] = struct{}{}
			}
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				allowed[id] = struct{}{}
			}
		}
	}
	for _, orgID := range userOrgIDs {
		if _, ok := allowed[orgID]; ok {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
	return false
}

// requireUserInFullAdminScope is the mutating sibling: requires the
// caller to full-admin (is_org_admin) at least one org the user
// belongs to. Used by updateRBACUser / deleteRBACUser.
func (s *Server) requireUserInFullAdminScope(c *gin.Context, userID string) bool {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		return true
	}
	userOrgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(c.Request.Context(), userID)
	if err != nil {
		slog.Error("scope check: GetUserOrgIDs failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "scope check failed"})
		return false
	}
	allowed := map[string]struct{}{}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				allowed[id] = struct{}{}
			}
		}
	}
	for _, orgID := range userOrgIDs {
		if _, ok := allowed[orgID]; ok {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
	return false
}

// jwtAdminFullAdminOrgIDs returns the slice of org IDs in which the
// caller has is_org_admin (full admin), or nil if the caller is super
// admin (X-Admin-Token bypass) / dev mode (no auth configured).
//
// Read-only admin orgs are intentionally excluded — this helper is used
// by mutating membership handlers that must reject RO admins regardless
// of org scope. RO admins are blocked at orgScopingMiddleware for routes
// with :org_id, but membership routes have :user_id (not :org_id), so
// the handler must enforce the read-only-rejection itself.
//
// Returns (nil, true) for super admin / dev mode (caller may target any
// org). Returns (orgIDs, false) for jwt_admin. Returns ([], false) for
// jwt_admin with no full-admin orgs (RO-admin-only — should be rejected).
func jwtAdminFullAdminOrgIDs(c *gin.Context) (orgIDs []string, isSuperOrDev bool) {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		return nil, true
	}
	if v, ok := c.Get("admin_org_ids"); ok {
		if ids, ok := v.([]string); ok {
			return ids, false
		}
	}
	return []string{}, false
}

// errScopeMissingAdminOrgIDs is returned by resolveListUsersScope when the
// caller is a jwt_admin but neither admin_org_ids nor admin_readonly_org_ids
// is present in the gin context. The middleware sets both atomically, so a
// missing value means a middleware wiring bug; we fail closed instead of
// falling through to "no scope" (which would have leaked every user
// cluster-wide).
var errScopeMissingAdminOrgIDs = errors.New("admin scope context missing")

// resolveListUsersScope returns the org IDs the caller may see, or nil when
// the caller is a super-admin (X-Admin-Token) or dev-mode (no auth
// configured) and may see everything.
//
// JWT org-admins are restricted to the merged set of admin_org_ids and
// admin_readonly_org_ids context values, populated by adminAuthMiddleware.
// Read-only admins see users in their RO scope just like full admins (for
// list/read endpoints); mutating endpoints have a separate full-admin gate
// (requireUserInFullAdminScope).
//
// Fail-closed semantics:
//
//   - jwt_admin with neither key set     -> error (middleware bug; deny).
//   - jwt_admin with empty merged slice  -> ([], nil) (legitimate: no orgs).
//   - admin_token                        -> (nil, nil) (super-admin pass-through).
//   - empty auth_method (dev mode)       -> (nil, nil) (no auth configured).
//   - any other auth_method              -> error (unexpected; deny).
func resolveListUsersScope(c *gin.Context) ([]string, error) {
	switch c.GetString("auth_method") {
	case "admin_token":
		// Super-admin (X-Admin-Token): unrestricted.
		return nil, nil
	case "":
		// Dev mode: no admin auth configured, no scope context to read.
		// Matches the pass-through other helpers (jwtAdminFullAdminOrgIDs,
		// inScope) give for non-jwt callers.
		return nil, nil
	case "jwt_admin":
		// Merge full + read-only admin orgs, dedup. Both keys must be
		// present — the middleware always sets them together, even
		// when one of the slices is empty.
		fullRaw, fullOK := c.Get("admin_org_ids")
		roRaw, roOK := c.Get("admin_readonly_org_ids")
		if !fullOK && !roOK {
			return nil, errScopeMissingAdminOrgIDs
		}
		seen := map[string]struct{}{}
		merged := make([]string, 0)
		if fullOK {
			if ids, ok := fullRaw.([]string); ok {
				for _, id := range ids {
					if _, dup := seen[id]; dup {
						continue
					}
					seen[id] = struct{}{}
					merged = append(merged, id)
				}
			}
		}
		if roOK {
			if ids, ok := roRaw.([]string); ok {
				for _, id := range ids {
					if _, dup := seen[id]; dup {
						continue
					}
					seen[id] = struct{}{}
					merged = append(merged, id)
				}
			}
		}
		return merged, nil
	default:
		// Unexpected auth_method — middleware contract violation. Deny.
		return nil, errScopeMissingAdminOrgIDs
	}
}

func (s *Server) listRBACUsers(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	limit, offset := parsePaginationParams(c, 50)

	scopedOrgIDs, err := resolveListUsersScope(c)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list users",
			"admin_rbac_user: resolveListUsersScope failed", "err", err)
		return
	}

	filter := db.UserFilter{
		OrgID:        c.Query("org_id"),
		Search:       c.Query("search"),
		GroupIDs:     c.QueryArray("group_id"),
		Role:         c.Query("role"),
		ScopedOrgIDs: scopedOrgIDs,
	}

	// Validate role early — unknown values would silently match nothing.
	switch filter.Role {
	case "", db.UserRoleOrgAdmin, db.UserRoleAdmin, db.UserRoleMember:
		// ok
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role filter"})
		return
	}

	users, total, err := s.db.ListUsersFilteredPaginated(c.Request.Context(), filter, limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list users",
			"admin_rbac_user: ListUsersFilteredPaginated failed", "err", err)
		return
	}

	userIDs := make([]string, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	memberships, err := s.db.ListGroupMembershipsForUsers(c.Request.Context(), userIDs, filter.ScopedOrgIDs)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list users",
			"admin_rbac_user: ListGroupMembershipsForUsers failed", "err", err)
		return
	}

	items := make([]userListItem, len(users))
	for i, u := range users {
		items[i] = userListItem{User: u, Groups: memberships[u.ID]}
		if items[i].Groups == nil {
			items[i].Groups = []rbac.UserGroupMembership{}
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) getRBACUser(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	userID := c.Param("user_id")
	if !s.requireUserInCallerScope(c, userID) {
		return
	}
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("get user: db read failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read user"})
		return
	}
	if user == nil {
		// Generic 403 — never reveal "exists in another org" vs "doesn't exist".
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (s *Server) updateRBACUser(c *gin.Context) {
	userID := c.Param("user_id")
	if !s.requireUserInFullAdminScope(c, userID) {
		return
	}

	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("update user: db read failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}

	var input struct {
		KYC      *bool          `json:"kyc"`
		Banned   *bool          `json:"banned"`
		Note     *string        `json:"note"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_user: invalid update body", "user_id", userID, "err", err)
		return
	}

	if input.KYC != nil {
		user.KYC = *input.KYC
	}
	if input.Banned != nil {
		user.Banned = *input.Banned
	}
	if input.Note != nil {
		user.Note = *input.Note
	}
	if input.Metadata != nil {
		user.Metadata = input.Metadata
	}

	// Capture before-image for audit log.
	before := map[string]any{
		"kyc":      user.KYC,
		"banned":   user.Banned,
		"note":     user.Note,
		"metadata": user.Metadata,
	}

	if err := s.db.UpdateUser(c.Request.Context(), user); err != nil {
		slog.Error("update user: db write failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	// Invalidate cache for this user
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), user.ID)

	// If user was just banned, revoke all their refresh tokens for immediate session termination
	if input.Banned != nil && *input.Banned {
		revoked, revokeErr := s.db.RevokeRefreshTokensBySubject(c.Request.Context(), user.ExternalID)
		if revokeErr != nil {
			slog.Warn("failed to revoke refresh tokens for banned user", "user", user.ExternalID, "error", revokeErr)
		} else if revoked > 0 {
			slog.Info("revoked refresh tokens for banned user", "count", revoked, "user", user.ExternalID)
		}
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeUser, user.ID, user.ExternalID,
		before,
		map[string]any{
			"kyc":      user.KYC,
			"banned":   user.Banned,
			"note":     user.Note,
			"metadata": user.Metadata,
		})

	c.JSON(http.StatusOK, user)
}

func (s *Server) getUserLinkedAddresses(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	userID := c.Param("user_id")
	if !s.requireUserInCallerScope(c, userID) {
		return
	}

	// Get user to find their external ID (DID)
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("get linked addresses: db read failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}

	// Get linked ETH addresses
	links, err := s.db.GetEthAddressesByDID(c.Request.Context(), user.ExternalID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read linked addresses",
			"admin_rbac_user: GetEthAddressesByDID failed", "user_id", user.ID, "err", err)
		return
	}

	// Transform to match expected frontend format
	type AddressResponse struct {
		Address       string  `json:"address"`
		VerifiedAt    string  `json:"verified_at"`
		ENSName       *string `json:"ens_name,omitempty"`
		ENSResolvedAt *string `json:"ens_resolved_at,omitempty"`
	}
	addresses := make([]AddressResponse, 0, len(links))
	for _, link := range links {
		addresses = append(addresses, AddressResponse{
			Address:       link.EthAddress,
			VerifiedAt:    link.VerifiedAt,
			ENSName:       link.ENSName,
			ENSResolvedAt: link.ENSResolvedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"addresses": addresses})
}

func (s *Server) deleteRBACUser(c *gin.Context) {
	userID := c.Param("user_id")
	if !s.requireUserInFullAdminScope(c, userID) {
		return
	}

	// Check if user exists
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("delete user: db read failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}

	// Delete all memberships for this user first
	memberships, err := s.db.ListUserMemberships(c.Request.Context(), userID)
	if err != nil {
		slog.Error("delete user: list memberships failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}
	for _, membership := range memberships {
		if err := s.db.DeleteMembership(c.Request.Context(), membership.ID); err != nil {
			slog.Error("delete user: membership delete failed", "user_id", userID, "membership_id", membership.ID, "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
			return
		}
	}

	// Delete the user
	if err := s.db.DeleteUser(c.Request.Context(), userID); err != nil {
		slog.Error("delete user: db delete failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}

	// Invalidate cache for this user
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	s.recordAuditAction(c, rbac.AuditActionDelete, rbac.ResourceTypeUser, user.ID, user.ExternalID,
		map[string]any{"external_id": user.ExternalID, "banned": user.Banned, "kyc": user.KYC},
		nil)

	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}

// Membership handlers

// membershipListItem is a membership-with-details plus a server-computed
// `expired` flag, so the admin UI can tell a live time-boxed grant from one
// whose window has already lapsed. `expired` is computed against the same UTC
// clock the RBAC resolver uses for its `expires_at > NOW()` access filter
// (RD-1157), so the badge the UI shows matches enforcement exactly. The raw
// expires_at is still carried on the embedded membership.
type membershipListItem struct {
	Membership *rbac.UserMembership `json:"membership"`
	Group      *rbac.Group          `json:"group"`
	Expired    bool                 `json:"expired"`
}

// withExpiryStatus maps memberships-with-details to list items, flagging any
// whose expires_at is in the past relative to now. A nil expires_at is a
// permanent membership and is never flagged expired.
func withExpiryStatus(memberships []*rbac.MembershipWithDetails, now time.Time) []membershipListItem {
	items := make([]membershipListItem, 0, len(memberships))
	for _, m := range memberships {
		if m == nil {
			continue
		}
		expired := m.Membership != nil && m.Membership.ExpiresAt != nil && m.Membership.ExpiresAt.Before(now)
		items = append(items, membershipListItem{Membership: m.Membership, Group: m.Group, Expired: expired})
	}
	return items
}

func (s *Server) listUserMemberships(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	userID := c.Param("user_id")
	// Caller must share at least one org with the user — prevents
	// enumeration of which groups in which orgs a multi-org user
	// belongs to (security audit H6).
	if !s.requireUserInCallerScope(c, userID) {
		return
	}
	memberships, err := s.db.ListUserMembershipsWithDetails(c.Request.Context(), userID)
	if err != nil {
		slog.Error("list memberships: db read failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read memberships"})
		return
	}
	// Filter memberships to caller's scope (full or read-only admin
	// orgs). Super-admin sees everything. Pre-fix, the response
	// enumerated all of a multi-org user's memberships including
	// foreign orgs.
	if c.GetString("auth_method") == "jwt_admin" {
		allowed := map[string]struct{}{}
		if ids, ok := c.Get("admin_org_ids"); ok {
			if list, ok := ids.([]string); ok {
				for _, id := range list {
					allowed[id] = struct{}{}
				}
			}
		}
		if ids, ok := c.Get("admin_readonly_org_ids"); ok {
			if list, ok := ids.([]string); ok {
				for _, id := range list {
					allowed[id] = struct{}{}
				}
			}
		}
		filtered := memberships[:0]
		for _, m := range memberships {
			if m.Group == nil {
				continue
			}
			if _, ok := allowed[m.Group.OrgID]; ok {
				filtered = append(filtered, m)
			}
		}
		memberships = filtered
	}
	c.JSON(http.StatusOK, withExpiryStatus(memberships, time.Now().UTC()))
}

// parseMembershipExpiry reads the optional `expires_at` field of a
// membership-create request — the configurable end of a time-boxed access
// window (e.g. a regulator profile granted for 24h / 7 days,
// RD-1145). nil or empty means a permanent membership (no expiry). A present
// value must be an RFC3339 timestamp strictly in the future; it is normalised
// to UTC to line up with the `expires_at > NOW()` filter the resolver enforces
// at access-decision time. On a malformed or non-future value it writes a 400
// and returns ok=false so the caller aborts before touching the DB.
func parseMembershipExpiry(c *gin.Context, raw *string) (*time.Time, bool) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(*raw))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be an RFC3339 timestamp"})
		return nil, false
	}
	if !t.After(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be in the future"})
		return nil, false
	}
	utc := t.UTC()
	return &utc, true
}

func (s *Server) createUserMembership(c *gin.Context) {
	userID := c.Param("user_id")

	// RD-942 Finding 1: gate the handler on the target user being in the
	// caller's full-admin scope BEFORE we look at the request body. Pre-fix,
	// the response-code path was a user-enumeration oracle:
	//
	//   201 Created                       → user exists, not yet in group
	//   409 Conflict ("already a member") → user exists and is in group
	//   500 Internal Server Error         → user does NOT exist (FK failed)
	//
	// A tier-2 admin who learned a foreign user UUID via logs / support /
	// screenshots could verify "this user exists" by attempting an add. UUID
	// space (128 bits) was the only barrier; the response-code distinction
	// turned the handler into a clean primitive for any future bug that leaks
	// a UUID.
	//
	// The legitimate "onboard an external user to my org" flow now goes
	// through POST /orgs/:org_id/memberships/by-did (RD-945), which auto-
	// provisions a user from a DID and inserts the membership in one round
	// trip — no super-admin handoff and no UUID-based hack-path.
	if !s.requireUserInFullAdminScope(c, userID) {
		return
	}

	var input struct {
		GroupID   string  `json:"group_id" binding:"required"`
		ExpiresAt *string `json:"expires_at"` // optional RFC3339; time-boxed access window (RD-1145)
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Cross-org isolation (RD-917 §3): the route is /users/:user_id/memberships
	// — no :org_id, so orgScopingMiddleware cannot enforce. Look up the target
	// group and verify the caller full-admins its org. Pre-fix, a tier-2 admin
	// of orgA could add a user to any group in orgB, including an
	// is_org_admin group, which was a cross-tenant escalation.
	group, err := s.db.GetGroup(c.Request.Context(), input.GroupID)
	if err != nil {
		slog.Error("create membership: get group failed", "group_id", input.GroupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create membership"})
		return
	}
	if group == nil {
		// Same opaque error as the cross-org case so a tier-2 admin
		// cannot probe the existence of group IDs in other orgs.
		c.JSON(http.StatusForbidden, gin.H{"error": errMembershipForeignOrg})
		return
	}
	if allowedOrgIDs, isSuperOrDev := jwtAdminFullAdminOrgIDs(c); !isSuperOrDev {
		if !slices.Contains(allowedOrgIDs, group.OrgID) {
			c.JSON(http.StatusForbidden, gin.H{"error": errMembershipForeignOrg})
			return
		}
	}

	// is_org_admin escalation gate (RD-1099): adding a member to an org-admin
	// group mints a new org admin — a peer who could ban/demote the granter —
	// so it is super-admin-only, mirroring the group-CRUD gates. After the
	// foreign-org check so cross-tenant probes stay opaque.
	if denyJWTAdminTouchOrgAdminGroup(c, group) {
		return
	}
	// RD-1107: super-admin manages org-admin-group membership only (minting);
	// regular-group membership is per-org tenant management (the org admin's job).
	if denyOperatorRegularGroup(c, group) {
		return
	}

	// Optional time-boxed access window (RD-1145). Parsed after the
	// authz gates so a malformed-timestamp 400 only reaches a caller already
	// cleared for this group.
	expiresAt, ok := parseMembershipExpiry(c, input.ExpiresAt)
	if !ok {
		return
	}

	membership := &rbac.UserMembership{
		ID:        uuid.New().String(),
		UserID:    userID,
		GroupID:   input.GroupID,
		Source:    rbac.MembershipSourceAdmin,
		ExpiresAt: expiresAt,
	}

	if err := s.db.CreateMembership(c.Request.Context(), membership); err != nil {
		// Translate duplicate-key violations (user already in group) into
		// 409 Conflict — the request is idempotent from the client's POV
		// and existing test helpers (e2e/playwright/helpers/ui/auth-helpers.ts
		// :323) detect the existing-membership case via the 409 status. If
		// we collapsed everything to a generic 500, those helpers throw and
		// every test in a parallel worker race condition fails.
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "user is already a member of this group"})
			return
		}
		slog.Error("create membership: db insert failed", "user_id", userID, "group_id", input.GroupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create membership"})
		return
	}

	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	s.recordAuditActionScoped(c, rbac.AuditActionAssign, rbac.ResourceTypeMembership, membership.ID, group.Name, group.OrgID,
		nil,
		map[string]any{
			"user_id":    userID,
			"group_id":   group.ID,
			"org_id":     group.OrgID,
			"expires_at": membership.ExpiresAt, // nil = permanent; set = time-boxed window (RD-1145)
		})

	c.JSON(http.StatusCreated, membership)
}

// validateOnboardDID checks that an admin-supplied onboarding identifier is a
// usable DID before it is turned into a `users` row. Without this, a typo'd
// DID, the Privado/Billions wallet *app* DID (instead of the user's *account*
// DID), or arbitrary garbage was accepted verbatim and created a dead
// membership row that no real login (DID = the verified ZK-proof `From`) would
// ever match (RD-1098).
//
// It enforces two layers:
//   - The string must be a syntactically valid W3C DID — rejects non-DID
//     pastes (emails, addresses, names, truncated junk).
//   - For iden3-family DIDs (Privado / Polygon ID), the on-chain identifier
//     checksum must verify — rejects typo'd or truncated Privado DIDs.
//
// Non-iden3 DID methods are accepted on structure alone: they carry no
// iden3 checksum we can verify, and they never reach this endpoint in
// production (real identities are iden3 DIDs or `azuread:` subjects, the
// latter not being DIDs and provisioned via the Azure login flow, not here).
//
// LIMITATION: this cannot distinguish the user's account DID from the wallet
// app's own DID — both are valid iden3 DIDs differing only in the opaque
// identity-state segment. That mistake is caught only by "the onboarded DID
// must match the one the user authenticates with" (see operator docs).
func validateOnboardDID(did string) error {
	parsed, err := w3c.ParseDID(did)
	if err != nil {
		return fmt.Errorf("not a valid DID: %w", err)
	}
	switch core.DIDMethod(parsed.Method) {
	case core.DIDMethodIden3, core.DIDMethodPolygonID:
		if _, err := core.IDFromDID(*parsed); err != nil {
			return fmt.Errorf("invalid iden3 identifier (bad checksum/network): %w", err)
		}
	}
	return nil
}

// createMembershipByDID is the tier-2 onboarding path: an org admin can pull
// a known DID into their own org without going through super-admin. The DID
// → user_id translation that `createUserMembership` skips is done here by
// calling `EnsureUserExists` — so a not-yet-seen DID is provisioned on first
// onboarding instead of requiring a separate auth event first.
//
// Cross-org isolation (RD-945):
//
//   - Caller must full-admin :org_id (jwt_admin gate). Super-admin and dev
//     callers bypass.
//   - target group must live in :org_id. A tier-2 admin of Org A passing a
//     group_id from Org B is rejected with the same opaque "access denied"
//     string used by the sibling membership endpoints — never reveal
//     whether the group exists in another org.
//
// Information-leak safety: the response never echoes the user's existing
// memberships in other orgs (we return user_id + the membership row we just
// created, nothing more). A banned user is treated as not-found rather than
// surfacing the ban status to an org admin who may not be entitled to it.
//
// Default-group semantics: when EnsureUserExists creates a brand-new user
// here, we pass skipDefaultGroup=true. Users onboarded directly into a
// caller's group should not also land in `default` — the membership goes
// only where the admin asked. If the user already exists with a `default`
// membership (e.g. they previously self-authenticated on a different org's
// surface), this endpoint does not touch that membership. ADD semantics, not
// MOVE — symmetric with the existing remove path.
func (s *Server) createMembershipByDID(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		DID       string  `json:"did" binding:"required"`
		GroupID   string  `json:"group_id" binding:"required"`
		ExpiresAt *string `json:"expires_at"` // optional RFC3339; time-boxed access window (RD-1145)
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Cross-org gate. Same shape as the sibling createUserMembership: full
	// admin in :org_id, super-admin / dev bypass.
	if allowedOrgIDs, isSuperOrDev := jwtAdminFullAdminOrgIDs(c); !isSuperOrDev {
		if !slices.Contains(allowedOrgIDs, orgID) {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
	}

	// Validate the DID before any DB work. Trim first so a copy-pasted DID
	// with stray whitespace matches the canonical form the auth path stores
	// (`authResponse.From`). Fail-closed: a malformed/typo'd DID is rejected
	// here rather than silently provisioned into a dead membership row. The
	// error is opaque to the caller (DID format is not org-scoped, but raw
	// parser internals are never echoed); the real cause is logged server-side.
	input.DID = strings.TrimSpace(input.DID)
	if err := validateOnboardDID(input.DID); err != nil {
		slog.Warn("onboard-by-did: rejected invalid did", "org_id", orgID, "did", input.DID, "err", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid did"})
		return
	}

	// Target group must live in :org_id. Look it up and verify directly —
	// never trust the path-param org_id alone (a malformed group_id from
	// another org would otherwise sneak in under the caller's admin scope).
	group, err := s.db.GetGroup(c.Request.Context(), input.GroupID)
	if err != nil {
		slog.Error("onboard-by-did: get group failed", "group_id", input.GroupID, "org_id", orgID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create membership"})
		return
	}
	if group == nil || group.OrgID != orgID {
		// Opaque "not in your scope" — collapses "group exists in another
		// org" with "group does not exist at all" so org admins cannot
		// probe foreign-org group IDs.
		c.JSON(http.StatusForbidden, gin.H{"error": errMembershipForeignOrg})
		return
	}

	// is_org_admin escalation gate (RD-1099): onboarding a DID straight into an
	// org-admin group mints a new org admin (worse here than createUserMembership
	// — the DID is auto-provisioned, so an arbitrary external identity could be
	// made an admin). Super-admin-only. After the foreign-org check above.
	if denyJWTAdminTouchOrgAdminGroup(c, group) {
		return
	}
	// RD-1107: super-admin manages org-admin-group membership only (minting);
	// regular-group membership is per-org tenant management (the org admin's job).
	if denyOperatorRegularGroup(c, group) {
		return
	}

	// Optional time-boxed access window (RD-1145). Parsed before
	// EnsureUserExists so a malformed-timestamp 400 cannot leave a phantom
	// auto-provisioned user behind.
	expiresAt, ok := parseMembershipExpiry(c, input.ExpiresAt)
	if !ok {
		return
	}

	// DID → user_id translation. If the DID is not yet in `users`, create the
	// row (mirroring first-login behaviour). KYC starts false; KYC remains
	// admin-managed. skipDefaultGroup=true so the user does not also end up
	// in `default` — the admin explicitly chose which group to put them in.
	if s.rbacAccessCtrl == nil {
		// No RBAC controller wired (test scaffolding). Treat as internal
		// error rather than silently succeeding with a phantom user.
		slog.Error("onboard-by-did: rbac controller not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create membership"})
		return
	}
	user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), input.DID, false, true)
	if err != nil {
		slog.Error("onboard-by-did: ensure user", "did", input.DID, "org_id", orgID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to onboard user"})
		return
	}
	if user == nil {
		// Defensive: EnsureUserExists shouldn't return (nil, nil). If it
		// somehow does, treat as a server-side failure rather than leaking
		// it as a distinguishable 404 — the caller can retry on 500.
		slog.Error("onboard-by-did: ensure user returned nil without error", "did", input.DID, "org_id", orgID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to onboard user"})
		return
	}
	// We deliberately do NOT special-case banned users here. Ban is global
	// state an org admin shouldn't be able to enumerate by probing this
	// endpoint (201 vs 404 would distinguish "active" from "banned"). A
	// banned user can be inserted into a group; the ban gate fires at
	// auth-time (auth.go's Banned check rejects token issuance) and the
	// membership row is dormant until the ban is lifted.

	membership := &rbac.UserMembership{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		GroupID:   input.GroupID,
		Source:    rbac.MembershipSourceAdmin,
		ExpiresAt: expiresAt,
	}

	if err := s.db.CreateMembership(c.Request.Context(), membership); err != nil {
		// Idempotent repeat — the user is already in this group. Same 409
		// shape and message as the sibling endpoint so existing helpers
		// detect it identically.
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "user is already a member of this group"})
			return
		}
		slog.Error("onboard-by-did: create membership failed", "user_id", user.ID, "group_id", input.GroupID, "org_id", orgID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create membership"})
		return
	}

	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), user.ID)

	s.recordAuditActionScoped(c, rbac.AuditActionAssign, rbac.ResourceTypeMembership, membership.ID, group.Name, group.OrgID,
		nil,
		map[string]any{
			"user_id":       user.ID,
			"group_id":      group.ID,
			"org_id":        group.OrgID,
			"did":           input.DID,
			"onboarded_via": "by-did",
			"expires_at":    membership.ExpiresAt, // nil = permanent; set = time-boxed window (RD-1145)
		})

	c.JSON(http.StatusCreated, gin.H{
		"user_id":    user.ID,
		"membership": membership,
	})
}

func (s *Server) deleteUserMembership(c *gin.Context) {
	userID := c.Param("user_id")
	membershipID := c.Param("membership_id")

	// Same cross-org check as createUserMembership: look up the membership,
	// then its group, and verify caller full-admins the group's org.
	membership, err := s.db.GetMembership(c.Request.Context(), membershipID)
	if err != nil {
		slog.Error("delete membership: get failed", "membership_id", membershipID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete membership"})
		return
	}
	if membership == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errMembershipForeignOrg})
		return
	}
	group, err := s.db.GetGroup(c.Request.Context(), membership.GroupID)
	if err != nil {
		slog.Error("delete membership: get group failed", "group_id", membership.GroupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete membership"})
		return
	}
	if group == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errMembershipForeignOrg})
		return
	}
	if allowedOrgIDs, isSuperOrDev := jwtAdminFullAdminOrgIDs(c); !isSuperOrDev {
		if !slices.Contains(allowedOrgIDs, group.OrgID) {
			c.JSON(http.StatusForbidden, gin.H{"error": errMembershipForeignOrg})
			return
		}
	}

	// is_org_admin escalation gate (RD-1099): removing a member from an
	// org-admin group demotes an org admin — the "ban or demote the granter"
	// power the gate exists to prevent — so it is super-admin-only, symmetric
	// with the add path. After the foreign-org check so probes stay opaque.
	if denyJWTAdminTouchOrgAdminGroup(c, group) {
		return
	}
	// RD-1107: super-admin manages org-admin-group membership only (minting);
	// regular-group membership is per-org tenant management (the org admin's job).
	if denyOperatorRegularGroup(c, group) {
		return
	}

	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	if err := s.db.DeleteMembership(c.Request.Context(), membershipID); err != nil {
		slog.Error("delete membership: db delete failed", "membership_id", membershipID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete membership"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionRevoke, rbac.ResourceTypeMembership, membershipID, group.Name, group.OrgID,
		map[string]any{
			"user_id":  userID,
			"group_id": group.ID,
			"org_id":   group.OrgID,
		}, nil)

	c.JSON(http.StatusOK, gin.H{"message": "membership deleted"})
}

// Debugging handlers

func (s *Server) getEffectivePermissions(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	userID := c.Param("user_id")
	// Caller must share at least one org with the user. Prevents a
	// tier-2 admin from extracting the AllowedMethods / Claims /
	// ContractAccess map of foreign-org users (audit H3).
	if !s.requireUserInCallerScope(c, userID) {
		return
	}

	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("effective perms: db read failed", "user_id", userID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}

	// Get org slug from query param, default to "default".
	orgSlug := c.Query("org")
	if orgSlug == "" {
		orgSlug = "default"
	}

	// Audit H3: the ?org=<slug> parameter must also be in the caller's
	// scope. Otherwise a tier-2 admin in Org A can ask "what would
	// user X see in Org B" — a cross-org probe.
	if c.GetString("auth_method") == "jwt_admin" {
		targetOrg, err := s.db.GetOrganizationBySlug(c.Request.Context(), orgSlug)
		if err != nil {
			slog.Error("effective perms: org-by-slug failed", "slug", orgSlug, "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve org"})
			return
		}
		if targetOrg == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
		if !inScope(c, targetOrg.ID) {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
	}

	perms, err := s.rbacAccessCtrl.GetEffectivePermissions(c.Request.Context(), user.ExternalID, orgSlug)
	if err != nil {
		slog.Error("effective perms: resolve failed", "user_id", userID, "org", orgSlug, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute permissions"})
		return
	}

	c.JSON(http.StatusOK, perms)
}

func (s *Server) checkAccessAPI(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	var req rbac.AccessCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Audit H4: clamp the probe target to the caller's scope. The
	// raw endpoint is a permission-map enumeration oracle otherwise —
	// any tier-2 admin can ask arbitrary {did, orgSlug, method,
	// target} combinations across the cluster.
	if c.GetString("auth_method") == "jwt_admin" {
		// Resolve target org from request (OrgID preferred, OrgSlug fallback).
		var targetOrgID string
		switch {
		case req.OrgID != "":
			targetOrgID = req.OrgID
		case req.OrgSlug != "":
			org, err := s.db.GetOrganizationBySlug(c.Request.Context(), req.OrgSlug)
			if err != nil {
				slog.Error("check access: org-by-slug failed", "slug", req.OrgSlug, "err", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve org"})
				return
			}
			if org == nil {
				c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
				return
			}
			targetOrgID = org.ID
		default:
			// No org specified — disallow probing for JWT admins.
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
		if !inScope(c, targetOrgID) {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
		// Also clamp the probed user — caller must share an org with them.
		if req.UserExternalID != "" {
			user, err := s.db.GetUserByExternalID(c.Request.Context(), req.UserExternalID)
			if err == nil && user != nil {
				if !s.requireUserInCallerScope(c, user.ID) {
					return
				}
			}
		}
	}

	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), &req)
	if err != nil {
		slog.Error("check access: resolve failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check access"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) getCacheStats(c *gin.Context) {
	// Cache statistics expose cross-org cardinality. Restrict to
	// super-admin (cluster-wide observability tooling).
	if !requireSuperAdmin(c) {
		return
	}
	stats := s.rbacAccessCtrl.CacheStats()
	c.JSON(http.StatusOK, stats)
}

// getEthAddressCollisions lists ETH addresses linked to more than one DID.
// These may indicate intentional key sharing (e.g. shared deployer wallets)
// or a key-compromise event and should be reviewed by an administrator.
//
// Audit H5: pre-fix this returned every (eth_address, [DIDs]) collision
// across the system. A tier-2 admin in Org A could read DIDs and
// addresses from Org B users. Now restricted to super-admin (the only
// caller who legitimately needs the cluster-wide list); JWT admins
// receive only collisions involving at least one user in their org
// scope.
func (s *Server) getEthAddressCollisions(c *gin.Context) {
	collisions, err := s.db.GetAddressLinkCollisions(c.Request.Context())
	if err != nil {
		slog.Error("collisions: db read failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read collisions"})
		return
	}
	if c.GetString("auth_method") == "jwt_admin" {
		// Build allowed set of user IDs (members of any caller-scoped org).
		allowedOrgs := map[string]struct{}{}
		if ids, ok := c.Get("admin_org_ids"); ok {
			if list, ok := ids.([]string); ok {
				for _, id := range list {
					allowedOrgs[id] = struct{}{}
				}
			}
		}
		if ids, ok := c.Get("admin_readonly_org_ids"); ok {
			if list, ok := ids.([]string); ok {
				for _, id := range list {
					allowedOrgs[id] = struct{}{}
				}
			}
		}
		filtered := make([]*db.AddressLinkCollision, 0, len(collisions))
		for _, col := range collisions {
			// Keep the row if any of its DIDs maps to a user with
			// membership in an allowed org.
			keep := false
			for _, did := range col.DIDs {
				user, err := s.db.GetUserByExternalID(c.Request.Context(), did)
				if err != nil || user == nil {
					continue
				}
				orgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(c.Request.Context(), user.ID)
				if err != nil {
					continue
				}
				for _, orgID := range orgIDs {
					if _, ok := allowedOrgs[orgID]; ok {
						keep = true
						break
					}
				}
				if keep {
					break
				}
			}
			if keep {
				filtered = append(filtered, col)
			}
		}
		collisions = filtered
	}
	c.JSON(http.StatusOK, gin.H{"collisions": collisions, "count": len(collisions)})
}

// inScope returns true if the JWT-admin caller has full or read-only
// admin privileges on orgID. For super-admin / dev mode, always true.
func inScope(c *gin.Context, orgID string) bool {
	if c.GetString("auth_method") != "jwt_admin" {
		return true
	}
	if orgID == "" {
		return false
	}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				if id == orgID {
					return true
				}
			}
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				if id == orgID {
					return true
				}
			}
		}
	}
	return false
}
