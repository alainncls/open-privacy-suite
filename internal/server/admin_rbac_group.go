package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/crypto"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate slug format before database insertion
	if errMsg := validateSlug(input.Slug); errMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	// Escalation prevention: JWT admins (tier 2) cannot create org admin or
	// readonly admin groups. Only super admins (X-Admin-Token) can mint
	// is_org_admin or is_org_readonly_admin groups (RD-866).
	if c.GetString("auth_method") == "jwt_admin" && (input.IsOrgAdmin || input.IsOrgReadonlyAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "only super admin can create org admin or readonly admin groups"})
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
		// Check for unique constraint violation (duplicate slug in org)
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "group with this slug already exists in this organization"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, group)
}

func (s *Server) getGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.JSON(http.StatusOK, group)
}

func (s *Server) updateGroup(c *gin.Context) {
	groupID := c.Param("group_id")

	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Escalation prevention: JWT admins (tier 2) cannot set is_org_admin or
	// is_org_readonly_admin to true. Only super admins (X-Admin-Token) can
	// promote groups to (readonly) org admin status (RD-866).
	if c.GetString("auth_method") == "jwt_admin" {
		if (input.IsOrgAdmin != nil && *input.IsOrgAdmin) || (input.IsOrgReadonlyAdmin != nil && *input.IsOrgReadonlyAdmin) {
			c.JSON(http.StatusForbidden, gin.H{"error": "only super admin can set org admin or readonly admin status on groups"})
			return
		}
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

	if err := s.db.UpdateGroup(c.Request.Context(), group); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for group members
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	c.JSON(http.StatusOK, group)
}

func (s *Server) deleteGroup(c *gin.Context) {
	groupID := c.Param("group_id")

	// Look up the group first so we can reject deletion of system rows
	// before invalidating cache or attempting the delete.
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if group != nil && group.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "system group cannot be deleted"})
		return
	}

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	if err := s.db.DeleteGroup(c.Request.Context(), groupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group deleted"})
}

// Group Access handlers

func (s *Server) getGroupAccess(c *gin.Context) {
	groupID := c.Param("group_id")
	access, err := s.db.GetGroupAccess(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err == nil && group != nil && group.ParentID != nil {
		s.populateEffectiveClaims(c.Request.Context(), group, access)
	}

	// Mask API key in response
	maskGroupAccessAPIKey(access)

	c.JSON(http.StatusOK, access)
}

func (s *Server) setGroupAccess(c *gin.Context) {
	groupID := c.Param("group_id")

	// Verify group exists
	group, err := s.db.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
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

	var input struct {
		AllowedMethods  []string     `json:"allowed_methods"`
		Claims          []rbac.Claim `json:"claims"`
		RateLimitRPS    *int         `json:"rate_limit_rps"`
		RateLimitDaily  *int         `json:"rate_limit_daily"`
		RPCAPIKey       *string      `json:"rpc_api_key"`
		RPCAPIKeyHeader *string      `json:"rpc_api_key_header"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate header name (when explicitly provided & non-empty) before any
	// DB write — letters, digits, hyphens only. Empty / nil falls back to the
	// configured default at request time.
	var headerName string
	if input.RPCAPIKeyHeader != nil {
		headerName = strings.TrimSpace(*input.RPCAPIKeyHeader)
		if headerName != "" && !proxy.ValidAPIKeyHeader(headerName) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "rpc_api_key_header must contain only letters, digits, and hyphens"})
			return
		}
	}

	// Expand wildcard "*" in allowed_methods to the full explicit method list.
	// The UI should never send "*" but the API accepts it for programmatic use.
	input.AllowedMethods = rbac.ExpandWildcardMethods(input.AllowedMethods)

	// Expand claim hierarchy (admin → deploy + upgrade).
	input.Claims = rbac.ExpandClaims(input.Claims)

	// Validate that allowed_methods match the claims
	// e.g., debug_traceTransaction requires "deploy" claim
	if err := rbac.ValidateMethodsMatchClaims(input.AllowedMethods, input.Claims); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	access := &rbac.GroupAccess{
		GroupID:         groupID,
		AllowedMethods:  input.AllowedMethods,
		Claims:          input.Claims,
		RateLimitRPS:    input.RateLimitRPS,
		RateLimitDaily:  input.RateLimitDaily,
		RPCAPIKey:       input.RPCAPIKey,
		RPCAPIKeyHeader: headerName,
	}

	if existing != nil {
		access.ID = existing.ID
		if err := s.db.UpdateGroupAccess(c.Request.Context(), access); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		access.ID = uuid.New().String()
		if err := s.db.CreateGroupAccess(c.Request.Context(), access); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// Invalidate cache for group members
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if group == nil || group.OrgID != orgID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "group " + gid + " not found in this organization"})
			return
		}

		// Count grants and get contract addresses
		grants, err := s.db.ListContractGrantsByGroup(c.Request.Context(), gid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			for _, contract := range contracts {
				contractAddresses = append(contractAddresses, contract.Address)
			}
		}

		// Count members
		members, err := s.db.ListGroupMembers(c.Request.Context(), gid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
