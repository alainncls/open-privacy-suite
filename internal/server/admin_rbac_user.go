package server

import (
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

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

// resolveListUsersScope returns the org IDs the caller may see, or nil when
// the caller is a super-admin (X-Admin-Token) and may see everything.
//
// JWT org-admins are restricted to the orgs in their admin_org_ids context
// value, populated by adminAuthMiddleware. An empty slice means the caller
// has no accessible orgs and the list will be empty.
func resolveListUsersScope(c *gin.Context) []string {
	if c.GetString("auth_method") == "admin_token" {
		return nil
	}
	if v, ok := c.Get("admin_org_ids"); ok {
		if ids, ok := v.([]string); ok {
			return ids
		}
	}
	// Dev mode (no auth configured) reaches here when admin_org_ids was
	// never set. Treat as super-admin: no scope.
	return nil
}

func (s *Server) listRBACUsers(c *gin.Context) {
	limit, offset := parsePaginationParams(c, 50)

	filter := db.UserFilter{
		OrgID:        c.Query("org_id"),
		Search:       c.Query("search"),
		GroupIDs:     c.QueryArray("group_id"),
		Role:         c.Query("role"),
		ScopedOrgIDs: resolveListUsersScope(c),
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userIDs := make([]string, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	memberships, err := s.db.ListGroupMembershipsForUsers(c.Request.Context(), userIDs, filter.ScopedOrgIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Transform to match expected frontend format
	type AddressResponse struct {
		Address      string  `json:"address"`
		VerifiedAt   string  `json:"verified_at"`
		ENSName      *string `json:"ens_name,omitempty"`
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

func (s *Server) listUserMemberships(c *gin.Context) {
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
	c.JSON(http.StatusOK, memberships)
}

func (s *Server) createUserMembership(c *gin.Context) {
	userID := c.Param("user_id")

	var input struct {
		GroupID string `json:"group_id" binding:"required"`
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

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: input.GroupID,
		Source:  rbac.MembershipSourceAdmin,
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
			"user_id":  userID,
			"group_id": group.ID,
			"org_id":   group.OrgID,
		})

	c.JSON(http.StatusCreated, membership)
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
		DID     string `json:"did" binding:"required"`
		GroupID string `json:"group_id" binding:"required"`
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
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: input.GroupID,
		Source:  rbac.MembershipSourceAdmin,
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
