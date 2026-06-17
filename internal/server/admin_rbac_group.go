package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/crypto"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// Deny messages for the is_org_admin escalation gate. Referenced from the
// handlers and from admin_tiers_test.go so the test never duplicates the
// literal — flipping the policy here automatically updates the assertion.
//
// is_org_readonly_admin is intentionally NOT in this gate: a tier-2 org
// admin granting RO-admin to a peer is delegation (strict subset of own
// permissions), not escalation. is_org_admin granting still requires the
// X-Admin-Token path because it creates a peer who could ban or demote
// the granter.
const (
	errCreateOrgAdminGroupSuperOnly = "only super admin can create org admin groups"
	errSetOrgAdminStatusSuperOnly   = "only super admin can change org admin status on groups"
	errDeleteOrgAdminGroupSuperOnly = "only super admin can delete org admin groups"

	// Assigning a member to, removing a member from, or reshaping the
	// group_access of an is_org_admin group confers or strips full org-admin —
	// the same escalation as minting the group itself. Reserved for super admin;
	// enforced by denyJWTAdminTouchOrgAdminGroup on the membership and
	// set-access surfaces (RD-1099). The batch-delete path reuses
	// errDeleteOrgAdminGroupSuperOnly since it is a deletion.
	errModifyOrgAdminGroupSuperOnly = "only super admin can modify membership or access of org admin groups"
)

// errBatchContainsOrgAdminGroup is returned from inside the batchDeleteGroups
// transaction when a tier-2 (jwt_admin) caller's batch includes an
// is_org_admin group. It aborts (rolls back) the whole batch and is translated
// to a 403 outside the tx — batch deletion must not be a back door around the
// per-group is_org_admin gate that deleteGroup enforces (RD-1099).
var errBatchContainsOrgAdminGroup = errors.New("batch contains org admin group")

// denyJWTAdminTouchOrgAdminGroup enforces the is_org_admin escalation gate on
// the membership and group-access surfaces, mirroring the gate already on
// group create/update/delete (errCreateOrgAdminGroupSuperOnly et al.).
// Assigning a member to, removing a member from, or reshaping the access of an
// is_org_admin group confers or strips full org-admin — a peer who can
// ban/demote the granter — so it is reserved for super admin (X-Admin-Token).
//
// Tier-2 jwt_admin callers get a 403; super-admin ("admin_token") and dev ("")
// pass through. is_org_readonly_admin groups are intentionally NOT gated
// (delegation, a strict subset of tier-2's own powers — see the createGroup
// rationale). Returns true and writes the 403 when the caller must be stopped;
// the handler must then return. Call AFTER the cross-org / foreign-org check so
// the opaque foreign-org error fires first for cross-tenant probes.
func denyJWTAdminTouchOrgAdminGroup(c *gin.Context, group *rbac.Group) bool {
	if group != nil && group.IsOrgAdmin && c.GetString("auth_method") == "jwt_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": errModifyOrgAdminGroupSuperOnly})
		return true
	}
	return false
}

// Org-admin group invariants (RD-968). The "org admin" role maps to three
// independent fields (is_org_admin, is_org_readonly_admin, group_access.claims +
// allowed_methods); these messages back the server-side checks that stop callers
// from persisting a combination that contradicts itself. The DB also carries a
// CHECK constraint for the mutual-exclusion rule (migration 060) as a backstop.
const (
	// A group is either a full org admin OR a read-only org admin OR neither —
	// never both. is_org_admin already grants everything is_org_readonly_admin
	// would; the contradiction only invites a later "consolidate to read-only"
	// edit that silently strips RPC admin from every member (RD-968 Gap 2).
	errAdminRolesMutuallyExclusive = "a group cannot be both a full org admin and a read-only org admin"

	// Claims are dead data on org-admin groups: the resolver grants all claims on
	// all org contracts regardless of group_access.claims (RD-968 Gap 1). We reject
	// rather than silently ignore so stored config never contradicts effective access.
	errOrgAdminClaimsNotApplicable = "claims do not apply to org-admin groups — members receive all claims on every contract automatically; leave claims empty"

	// An org-admin group with no allowed methods grants all claims but zero callable
	// methods — silently useless (RD-968 Gap 3). Require an explicit method allowlist.
	errOrgAdminMethodsRequired = "org-admin groups must have at least one allowed method"
)

// Group handlers

func (s *Server) listGroups(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := parsePaginationParams(c, 50)

	// Parse optional filters
	filter := db.GroupListFilter{
		Search: c.Query("search"),
	}

	groups, total, err := s.db.ListGroupsWithAccessFiltered(c.Request.Context(), orgID, limit, offset, filter)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list groups",
			"admin_rbac_group: ListGroupsWithAccessFiltered failed",
			"org_id", orgID, "err", err)
		return
	}

	// Populate effective claims for child groups and mask API keys
	for i := range groups {
		if groups[i].Group != nil && groups[i].Group.ParentID != nil && groups[i].Access != nil {
			s.populateEffectiveClaims(c.Request.Context(), groups[i].Group, groups[i].Access)
		}
		if groups[i].Access != nil {
			maskGroupAccessAPIKey(groups[i].Access)
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": groups, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) createGroup(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		Slug               string  `json:"slug" binding:"required"`
		Name               string  `json:"name" binding:"required"`
		Description        string  `json:"description"`
		ParentID           *string `json:"parent_id"`
		IsOrgAdmin         bool    `json:"is_org_admin"`
		IsOrgReadonlyAdmin bool    `json:"is_org_readonly_admin"`
	}
	// Note: auto_created is intentionally NOT accepted from API input.
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_group: invalid create body", "org_id", orgID, "err", err)
		return
	}

	// Validate slug format before database insertion
	if errMsg := validateSlug(input.Slug); errMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	// Escalation prevention: JWT admins (tier 2) cannot create is_org_admin
	// groups — that would create a peer who could demote them. Only super
	// admins (X-Admin-Token) can mint is_org_admin (RD-866). Tier-2 *can*
	// create is_org_readonly_admin groups: RO-admin is a strict subset of
	// tier-2's permissions, so granting it is delegation, not escalation
	// (RD-917 §2 — see PR description).
	if c.GetString("auth_method") == "jwt_admin" && input.IsOrgAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": errCreateOrgAdminGroupSuperOnly})
		return
	}

	// Invariant (RD-968 Gap 2): a group is a full org admin XOR a read-only org
	// admin, never both. Enforced for every caller (super admin included) and
	// backed by a DB CHECK constraint (migration 060).
	if input.IsOrgAdmin && input.IsOrgReadonlyAdmin {
		c.JSON(http.StatusBadRequest, gin.H{"error": errAdminRolesMutuallyExclusive})
		return
	}

	// parent_id is accepted but ignored — groups are flat (no hierarchy).
	// The DB column is retained per expand-only migration policy.

	group := &rbac.Group{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		Slug:               input.Slug,
		Name:               input.Name,
		Description:        input.Description,
		Depth:              0,
		Path:               input.Slug,
		IsOrgAdmin:         input.IsOrgAdmin,
		IsOrgReadonlyAdmin: input.IsOrgReadonlyAdmin,
	}

	if err := s.db.CreateGroup(c.Request.Context(), group); err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": uniqueConflictMessage(err)})
			return
		}
		slog.Error("create group: db insert failed", "org_id", orgID, "slug", input.Slug, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create group"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionCreate, rbac.ResourceTypeGroup, group.ID, group.Name, group.OrgID,
		nil,
		map[string]any{
			"slug":                  group.Slug,
			"is_org_admin":          group.IsOrgAdmin,
			"is_org_readonly_admin": group.IsOrgReadonlyAdmin,
		})

	c.JSON(http.StatusCreated, group)
}

// isUniqueViolation reports whether err looks like a Postgres unique
// constraint violation. Implemented as a string match because the DB
// drivers in use (database/sql + lib/pq) bubble the message up rather than
// a typed error we can errors.As against.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

// uniqueConflictStatus returns 409 for unique-violation errors and 500 otherwise.
func uniqueConflictStatus(err error) int {
	if isUniqueViolation(err) {
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// uniqueConflictMessage maps the unique constraint that fired to a
// human-readable message. The DB has two relevant constraints on `groups`:
// `groups_org_id_slug_key` (slug) and `idx_groups_org_name_unique`
// (case-insensitive name; migration 049).
func uniqueConflictMessage(err error) string {
	if !isUniqueViolation(err) {
		return err.Error()
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "idx_groups_org_name_unique"):
		return "group with this name already exists in this organization (names are case-insensitive)"
	case strings.Contains(msg, "groups_org_id_slug_key"):
		return "group with this slug already exists in this organization"
	default:
		return "group with this slug or name already exists in this organization"
	}
}

// verifyGroupBelongsToPathOrg checks the loaded group's OrgID matches
// the :org_id in the request path. Required because routes like
// /orgs/:org_id/groups/:group_id/... LOOK scoped but the handler
// previously trusted the URL without re-verifying — a tier-2 admin of
// Org A could PUT /orgs/orgA/groups/<orgB-group-id>/... and seize an
// Org B group (audit C2).
//
// Returns true if the group is in the path org (caller may proceed).
// Returns false and writes a 403 otherwise. The error string matches
// the not-found shape so an attacker cannot distinguish "exists in
// another org" from "does not exist".
func verifyGroupBelongsToPathOrg(c *gin.Context, group *rbac.Group) bool {
	pathOrg := c.Param("org_id")
	if pathOrg == "" || group == nil || group.OrgID != pathOrg {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return false
	}
	return true
}

func (s *Server) getGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		slog.Error("get group: db read failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read group"})
		return
	}
	if !verifyGroupBelongsToPathOrg(c, group) {
		return
	}
	c.JSON(http.StatusOK, group)
}

func (s *Server) updateGroup(c *gin.Context) {
	groupID := c.Param("group_id")

	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		slog.Error("update group: get failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update group"})
		return
	}
	if !verifyGroupBelongsToPathOrg(c, group) {
		return
	}
	if group.IsSystem {
		// is_system rows are identity-immutable. Their group_access (methods,
		// claims) is editable via the dedicated PUT endpoint, restricted to
		// super admin. The group row itself (name/description/is_org_admin)
		// is locked.
		c.JSON(http.StatusForbidden, gin.H{"error": "system group cannot be modified"})
		return
	}

	var input struct {
		Name               *string `json:"name"`
		Description        *string `json:"description"`
		IsOrgAdmin         *bool   `json:"is_org_admin"`
		IsOrgReadonlyAdmin *bool   `json:"is_org_readonly_admin"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Escalation/DoS prevention: JWT admins (tier 2) cannot touch
	// is_org_admin in either direction.
	//
	//   true → tier-2 would mint a peer admin who could demote the granter.
	//   false → tier-2 demoting an existing admin group strips admin status
	//           from every member (including possibly themselves), causing
	//           an org-wide DoS that only super-admin can recover from.
	//
	// They CAN set is_org_readonly_admin — see the createGroup rationale
	// above (RD-866 / RD-917 §2).
	if c.GetString("auth_method") == "jwt_admin" && input.IsOrgAdmin != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errSetOrgAdminStatusSuperOnly})
		return
	}

	oldValue := map[string]any{
		"name":                  group.Name,
		"description":           group.Description,
		"is_org_admin":          group.IsOrgAdmin,
		"is_org_readonly_admin": group.IsOrgReadonlyAdmin,
	}

	if input.Name != nil {
		group.Name = *input.Name
	}
	if input.Description != nil {
		group.Description = *input.Description
	}
	if input.IsOrgAdmin != nil {
		group.IsOrgAdmin = *input.IsOrgAdmin
	}
	if input.IsOrgReadonlyAdmin != nil {
		group.IsOrgReadonlyAdmin = *input.IsOrgReadonlyAdmin
	}

	// Invariant (RD-968 Gap 2): reject the *resulting* state if it would make the
	// group both a full org admin and a read-only org admin. Checked on the merged
	// group (not just input) so toggling RO on a group that is already is_org_admin
	// is caught. Backed by a DB CHECK constraint (migration 060).
	if group.IsOrgAdmin && group.IsOrgReadonlyAdmin {
		c.JSON(http.StatusBadRequest, gin.H{"error": errAdminRolesMutuallyExclusive})
		return
	}

	if err := s.db.UpdateGroup(c.Request.Context(), group); err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": uniqueConflictMessage(err)})
			return
		}
		slog.Error("update group: db update failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update group"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionUpdate, rbac.ResourceTypeGroup, group.ID, group.Name, group.OrgID,
		oldValue,
		map[string]any{
			"name":                  group.Name,
			"description":           group.Description,
			"is_org_admin":          group.IsOrgAdmin,
			"is_org_readonly_admin": group.IsOrgReadonlyAdmin,
		})

	// Invalidate cache for group members
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	c.JSON(http.StatusOK, group)
}

func (s *Server) deleteGroup(c *gin.Context) {
	groupID := c.Param("group_id")

	// Look up the group first so we can reject deletion of system rows
	// AND of is_org_admin rows (the latter for jwt_admin only — same DoS
	// reasoning as the updateGroup demote gate above).
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		slog.Error("delete group: get failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete group"})
		return
	}
	if !verifyGroupBelongsToPathOrg(c, group) {
		return
	}
	if group != nil && group.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "system group cannot be deleted"})
		return
	}
	if group != nil && group.IsOrgAdmin && c.GetString("auth_method") == "jwt_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": errDeleteOrgAdminGroupSuperOnly})
		return
	}

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	if err := s.db.DeleteGroup(c.Request.Context(), groupID); err != nil {
		slog.Error("delete group: delete failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete group"})
		return
	}

	if group != nil {
		s.recordAuditActionScoped(c, rbac.AuditActionDelete, rbac.ResourceTypeGroup, group.ID, group.Name, group.OrgID,
			map[string]any{
				"slug":                  group.Slug,
				"is_org_admin":          group.IsOrgAdmin,
				"is_org_readonly_admin": group.IsOrgReadonlyAdmin,
			}, nil)
	}

	c.JSON(http.StatusOK, gin.H{"message": "group deleted"})
}

// Group Access handlers

func (s *Server) getGroupAccess(c *gin.Context) {
	groupID := c.Param("group_id")
	// Re-verify group belongs to path :org_id (audit C2). Pre-fix,
	// PUT /orgs/orgA/groups/<orgB-group-id>/access could read /
	// modify Org B's group_access.
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		slog.Error("get group access: get group failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read group"})
		return
	}
	if !verifyGroupBelongsToPathOrg(c, group) {
		return
	}

	access, err := s.db.GetGroupAccess(c.Request.Context(), groupID)
	if err != nil {
		slog.Error("get group access: db read failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read access"})
		return
	}
	if access == nil {
		// Return empty access if not set
		access = &rbac.GroupAccess{
			GroupID:        groupID,
			AllowedMethods: []string{},
			Claims:         []rbac.Claim{},
		}
	}

	// Compute effective claims for child groups
	if group.ParentID != nil {
		s.populateEffectiveClaims(c.Request.Context(), group, access)
	}

	// Mask API key in response
	maskGroupAccessAPIKey(access)

	c.JSON(http.StatusOK, access)
}

func (s *Server) setGroupAccess(c *gin.Context) {
	groupID := c.Param("group_id")

	// Verify group exists AND belongs to the path :org_id (audit C2).
	// Pre-fix this handler accepted any group_id under any orgA route
	// and would happily widen allowed_methods, set claims=[admin], or
	// rewrite rpc_api_key on a foreign-org group.
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		slog.Error("set group access: get group failed", "group_id", groupID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read group"})
		return
	}
	if !verifyGroupBelongsToPathOrg(c, group) {
		return
	}

	// is_system groups (e.g. the anonymous group from RD-870) have their
	// group_access editable, but only by super admin (X-Admin-Token). Tier-2
	// JWT admins are scoped to their own org; even if scoping is misconfigured
	// they should not be able to widen the rules anonymous traffic plays by.
	if group.IsSystem && c.GetString("auth_method") != "admin_token" {
		c.JSON(http.StatusForbidden, gin.H{"error": "system group access can only be modified by super admin (X-Admin-Token)"})
		return
	}

	// is_org_admin escalation gate (RD-1099): reshaping an admin group's access
	// (e.g. widening allowed_methods) changes what every org admin can do, so it
	// is super-admin-only — mirrors the membership and group-CRUD gates. Placed
	// after verifyGroupBelongsToPathOrg so foreign-org probes stay opaque.
	if denyJWTAdminTouchOrgAdminGroup(c, group) {
		return
	}

	var input struct {
		AllowedMethods []string     `json:"allowed_methods"`
		Claims         []rbac.Claim `json:"claims"`
		RateLimitRPS   *int         `json:"rate_limit_rps"`
		RateLimitDaily *int         `json:"rate_limit_daily"`
		RPCAPIKey      *string      `json:"rpc_api_key"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_group: invalid setGroupAccess body", "group_id", groupID, "err", err)
		return
	}

	// Expand wildcard "*" in allowed_methods to the full explicit method list.
	// The UI should never send "*" but the API accepts it for programmatic use.
	input.AllowedMethods = rbac.ExpandWildcardMethods(input.AllowedMethods)

	// Expand claim hierarchy (admin → deploy + upgrade).
	input.Claims = rbac.ExpandClaims(input.Claims)

	// Org-admin group invariants (RD-968 Gaps 1 & 3). On an is_org_admin group the
	// resolver grants ALL claims on ALL org contracts regardless of this row's
	// claims (computeOrgAdminPermissions), so:
	//   - reject any non-empty claims — they are dead data and would make the stored
	//     config contradict effective access (we reject rather than silently drop);
	//   - require a non-empty method allowlist — claims-on-all-contracts with zero
	//     callable methods is silently useless;
	//   - skip ValidateMethodsMatchClaims — effective claims are all-of-them, so the
	//     stored-claims-vs-methods check (which expects e.g. debug_* to be paired with
	//     the deploy claim) would wrongly reject legitimate org-admin method sets.
	// The method allowlist is still the source of truth for method gating even for
	// org admins (see docs/rbac) — that is why we require it rather than granting "*".
	if group.IsOrgAdmin {
		if len(input.Claims) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": errOrgAdminClaimsNotApplicable})
			return
		}
		if len(input.AllowedMethods) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": errOrgAdminMethodsRequired})
			return
		}
	} else if err := rbac.ValidateMethodsMatchClaims(input.AllowedMethods, input.Claims); err != nil {
		// Validator message lists the offending method/claim. Safe to
		// surface — no internal identifiers, just operator-supplied
		// input — but route through the helper for slog consistency.
		respondBadRequestAndLog(c, "method/claim mismatch",
			"admin_rbac_group: ValidateMethodsMatchClaims failed",
			"group_id", groupID, "err", err)
		return
	}

	// Encrypt API key before storing (if encryption key is configured)
	if input.RPCAPIKey != nil && *input.RPCAPIKey != "" {
		encrypted, err := crypto.Encrypt(*input.RPCAPIKey, s.config.RPCAPIKeyEncryptionKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt API key"})
			return
		}
		input.RPCAPIKey = &encrypted
	}

	// Check if access already exists
	existing, err := s.db.GetGroupAccess(c.Request.Context(), groupID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to set group access",
			"admin_rbac_group: GetGroupAccess failed", "group_id", groupID, "err", err)
		return
	}

	access := &rbac.GroupAccess{
		GroupID:        groupID,
		AllowedMethods: input.AllowedMethods,
		Claims:         input.Claims,
		RateLimitRPS:   input.RateLimitRPS,
		RateLimitDaily: input.RateLimitDaily,
		RPCAPIKey:      input.RPCAPIKey,
	}

	if existing != nil {
		access.ID = existing.ID
		if err := s.db.UpdateGroupAccess(c.Request.Context(), access); err != nil {
			respondInternalErrorAndLog(c, "failed to set group access",
				"admin_rbac_group: UpdateGroupAccess failed",
				"group_id", groupID, "err", err)
			return
		}
	} else {
		access.ID = uuid.New().String()
		if err := s.db.CreateGroupAccess(c.Request.Context(), access); err != nil {
			respondInternalErrorAndLog(c, "failed to set group access",
				"admin_rbac_group: CreateGroupAccess failed",
				"group_id", groupID, "err", err)
			return
		}
	}

	// Invalidate cache for group members
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	// L9: if this is the anonymous system group, also drop the
	// access controller's anonymous-row cache so the change takes
	// effect immediately on the next anonymous request (instead of
	// waiting for the 5s TTL to expire).
	if groupID == rbac.AnonymousGroupID {
		s.rbacAccessCtrl.InvalidateAnonymousAccess()
	}

	// Mask API key in response
	maskGroupAccessAPIKey(access)

	c.JSON(http.StatusOK, access)
}

// populateEffectiveClaims computes effective claims for a child group by walking
// up the parent hierarchy and intersecting claims at each level. It sets the
// EffectiveClaims and NarrowedByParent fields on the access struct.
func (s *Server) populateEffectiveClaims(ctx context.Context, group *rbac.Group, access *rbac.GroupAccess) {
	effective := make([]rbac.Claim, len(access.Claims))
	copy(effective, access.Claims)

	currentID := group.ParentID
	for currentID != nil {
		parentAccess, err := s.db.GetGroupAccess(ctx, *currentID)
		if err != nil {
			return // On error, leave effective claims unset
		}
		if parentAccess != nil {
			effective = rbac.IntersectClaims(effective, parentAccess.Claims)
		} else {
			// Parent has no access configured — no claims flow through
			effective = nil
			break
		}

		parent, err := s.db.GetGroup(ctx, *currentID)
		if err != nil || parent == nil {
			break
		}
		currentID = parent.ParentID
	}

	access.EffectiveClaims = effective
	// Narrowed if effective differs from stored claims
	if len(effective) != len(access.Claims) {
		access.NarrowedByParent = true
	} else {
		// Check if content differs (claims are sorted by ExpandClaims)
		for i, c := range effective {
			if c != access.Claims[i] {
				access.NarrowedByParent = true
				break
			}
		}
	}
}

// batchDeletePreview returns information about groups to be deleted.
// POST /orgs/:org_id/groups/batch-delete-preview
func (s *Server) batchDeletePreview(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		GroupIDs []string `json:"group_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_group: invalid batchDeletePreview body", "org_id", orgID, "err", err)
		return
	}

	if len(input.GroupIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_ids is required"})
		return
	}
	if len(input.GroupIDs) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many group_ids (max 200)"})
		return
	}

	type groupPreview struct {
		ID            string   `json:"id"`
		Name          string   `json:"name"`
		Slug          string   `json:"slug"`
		ContractCount int      `json:"contract_count"`
		MemberCount   int      `json:"member_count"`
		Contracts     []string `json:"contracts"` // contract addresses
	}

	var previews []groupPreview
	for _, gid := range input.GroupIDs {
		group, err := s.db.GetGroup(c.Request.Context(), gid)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to read group",
				"admin_rbac_group: GetGroup failed in batchDeletePreview",
				"group_id", gid, "err", err)
			return
		}
		// L10: opaque deny — pre-fix the message distinguished "exists
		// elsewhere" from "doesn't exist", letting a tier-2 admin probe
		// group IDs in other orgs. Match the errTargetForeignOrg shape.
		if group == nil || group.OrgID != orgID {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}

		// Count grants and get contract addresses
		grants, err := s.db.ListContractGrantsByGroup(c.Request.Context(), gid)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to list contract grants",
				"admin_rbac_group: ListContractGrantsByGroup failed",
				"group_id", gid, "err", err)
			return
		}

		var contractAddresses []string
		if len(grants) > 0 {
			contractIDs := make([]string, len(grants))
			for i, g := range grants {
				contractIDs[i] = g.ContractID
			}
			contracts, err := s.db.GetContractsByIDs(c.Request.Context(), contractIDs)
			if err != nil {
				respondInternalErrorAndLog(c, "failed to read contracts",
					"admin_rbac_group: GetContractsByIDs failed",
					"group_id", gid, "err", err)
				return
			}
			for _, contract := range contracts {
				contractAddresses = append(contractAddresses, contract.Address)
			}
		}

		// Count members
		members, err := s.db.ListGroupMembers(c.Request.Context(), gid)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to list group members",
				"admin_rbac_group: ListGroupMembers failed",
				"group_id", gid, "err", err)
			return
		}

		previews = append(previews, groupPreview{
			ID:            group.ID,
			Name:          group.Name,
			Slug:          group.Slug,
			ContractCount: len(grants),
			MemberCount:   len(members),
			Contracts:     contractAddresses,
		})
	}

	c.JSON(http.StatusOK, gin.H{"groups": previews})
}

// batchDeleteGroups deletes multiple groups atomically.
// POST /orgs/:org_id/groups/batch-delete
func (s *Server) batchDeleteGroups(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		GroupIDs []string `json:"group_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_group: invalid batchDeleteGroups body", "org_id", orgID, "err", err)
		return
	}

	if len(input.GroupIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_ids is required"})
		return
	}
	if len(input.GroupIDs) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many group_ids (max 200)"})
		return
	}

	err := s.db.WithTx(c.Request.Context(), func(tx *db.Tx) error {
		ctx := c.Request.Context()

		// Verify all groups belong to this org
		groups, err := tx.GetGroupsByIDs(ctx, orgID, input.GroupIDs)
		if err != nil {
			return fmt.Errorf("failed to get groups: %w", err)
		}
		foundIDs := make(map[string]bool, len(groups))
		for _, g := range groups {
			foundIDs[g.ID] = true
		}
		for _, gid := range input.GroupIDs {
			if !foundIDs[gid] {
				return fmt.Errorf("group %s not found in this organization", gid)
			}
		}

		// is_org_admin escalation gate (RD-1099): batch deletion must not be a
		// back door around deleteGroup's per-group gate. If a tier-2 (jwt_admin)
		// caller's batch includes any org-admin group, abort the whole batch.
		// Super-admin / dev are unaffected.
		if c.GetString("auth_method") == "jwt_admin" {
			for _, g := range groups {
				if g.IsOrgAdmin {
					return errBatchContainsOrgAdminGroup
				}
			}
		}

		// Delete each group with dependencies
		for _, gid := range input.GroupIDs {
			if err := tx.DeleteGroupWithDependenciesTx(ctx, gid); err != nil {
				return fmt.Errorf("failed to delete group %s: %w", gid, err)
			}
		}

		// Invalidate DB cache for all users in the org (must happen inside the tx
		// so rollback also rolls back the cache delete).
		if err := tx.InvalidateCacheForOrg(ctx, orgID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, errBatchContainsOrgAdminGroup) {
			// Tier-2 tried to batch-delete an org-admin group. Reuse the
			// deleteGroup gate's message (this is a deletion). RD-1099.
			c.JSON(http.StatusForbidden, gin.H{"error": errDeleteOrgAdminGroupSuperOnly})
			return
		}
		if strings.Contains(err.Error(), "not found") {
			// The "X not found" error is built by the closure above with
			// an attacker-supplied group_id concatenated in — surfacing
			// it would let a tier-2 admin probe foreign group IDs.
			// Collapse to a generic 400. RD-934.
			respondBadRequestAndLog(c, "one or more groups not found in this organization",
				"admin_rbac_group: batchDeleteGroups membership mismatch",
				"org_id", orgID, "err", err)
			return
		}
		respondInternalErrorAndLog(c, "failed to delete groups",
			"admin_rbac_group: batchDeleteGroups tx failed",
			"org_id", orgID, "err", err)
		return
	}

	// Tx committed — drop the in-memory cache for this org so live requests
	// see the new permission set immediately (no TTL wait).
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	c.JSON(http.StatusOK, gin.H{"deleted_count": len(input.GroupIDs)})
}

// maskGroupAccessAPIKey replaces the API key in a GroupAccess with a masked
// version showing only the last 4 characters. This prevents full API keys
// from being exposed in API responses.
func maskGroupAccessAPIKey(access *rbac.GroupAccess) {
	if access == nil || access.RPCAPIKey == nil || *access.RPCAPIKey == "" {
		return
	}
	masked := maskAPIKeyStr(*access.RPCAPIKey)
	access.RPCAPIKey = &masked
}

// maskAPIKeyStr returns a masked version of an API key for safe display.
// Shows only the last 4 characters prefixed with "****".
// Returns "" for empty keys, "****" for keys shorter than 4 characters.
func maskAPIKeyStr(key string) string {
	if key == "" {
		return ""
	}
	if len(key) < 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}
