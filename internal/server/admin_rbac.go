package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// registerRBACRoutes registers RBAC admin API endpoints.
func (s *Server) registerRBACRoutes(api *gin.RouterGroup) {
	// Organizations
	api.GET("/orgs", s.listOrganizations)
	api.POST("/orgs", s.createOrganization)
	api.GET("/orgs/:org_id", s.getOrganization)
	api.PUT("/orgs/:org_id", s.updateOrganization)

	// Groups
	api.GET("/orgs/:org_id/groups", s.listGroups)
	api.POST("/orgs/:org_id/groups", s.createGroup)
	api.GET("/orgs/:org_id/groups/:group_id", s.getGroup)
	api.PUT("/orgs/:org_id/groups/:group_id", s.updateGroup)
	api.DELETE("/orgs/:org_id/groups/:group_id", s.deleteGroup)
	api.GET("/orgs/:org_id/groups/:group_id/permissions", s.getGroupPermissions)
	api.PUT("/orgs/:org_id/groups/:group_id/permissions", s.setGroupPermissions)

	// Roles
	api.GET("/orgs/:org_id/roles", s.listRoles)
	api.POST("/orgs/:org_id/roles", s.createRole)
	api.GET("/orgs/:org_id/roles/:role_id", s.getRole)
	api.PUT("/orgs/:org_id/roles/:role_id", s.updateRole)
	api.DELETE("/orgs/:org_id/roles/:role_id", s.deleteRole)

	// Users
	api.GET("/users", s.listRBACUsers)
	api.GET("/users/:user_id", s.getRBACUser)
	api.PUT("/users/:user_id", s.updateRBACUser)

	// Memberships
	api.GET("/users/:user_id/memberships", s.listUserMemberships)
	api.POST("/users/:user_id/memberships", s.createUserMembership)
	api.DELETE("/users/:user_id/memberships/:membership_id", s.deleteUserMembership)

	// Contracts
	api.GET("/orgs/:org_id/contracts", s.listContractOwnerships)
	api.POST("/orgs/:org_id/contracts", s.createContractOwnership)
	api.PUT("/orgs/:org_id/contracts/:address", s.updateContractOwnership)
	api.DELETE("/orgs/:org_id/contracts/:address", s.deleteContractOwnership)

	// Debugging
	api.GET("/users/:user_id/effective-permissions", s.getEffectivePermissions)
	api.POST("/access/check", s.checkAccessAPI)
	api.GET("/cache/stats", s.getCacheStats)
}

// Organization handlers

func (s *Server) listOrganizations(c *gin.Context) {
	orgs, err := s.db.ListOrganizations(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, orgs)
}

func (s *Server) createOrganization(c *gin.Context) {
	var input struct {
		Slug     string         `json:"slug" binding:"required"`
		Name     string         `json:"name" binding:"required"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     input.Slug,
		Name:     input.Name,
		Settings: input.Settings,
	}
	if org.Settings == nil {
		org.Settings = make(map[string]any)
	}

	if err := s.db.CreateOrganization(c.Request.Context(), org); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, org)
}

func (s *Server) getOrganization(c *gin.Context) {
	orgID := c.Param("org_id")
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}
	c.JSON(http.StatusOK, org)
}

func (s *Server) updateOrganization(c *gin.Context) {
	orgID := c.Param("org_id")

	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	var input struct {
		Slug     *string        `json:"slug"`
		Name     *string        `json:"name"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Slug != nil {
		org.Slug = *input.Slug
	}
	if input.Name != nil {
		org.Name = *input.Name
	}
	if input.Settings != nil {
		org.Settings = input.Settings
	}

	if err := s.db.UpdateOrganization(c.Request.Context(), org); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

// Group handlers

func (s *Server) listGroups(c *gin.Context) {
	orgID := c.Param("org_id")
	groups, err := s.db.ListGroups(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, groups)
}

func (s *Server) createGroup(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		Slug        string  `json:"slug" binding:"required"`
		Name        string  `json:"name" binding:"required"`
		Description string  `json:"description"`
		ParentID    *string `json:"parent_id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Calculate depth and path
	var depth int
	var path string

	if input.ParentID != nil {
		parent, err := s.db.GetGroup(c.Request.Context(), *input.ParentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if parent == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "parent group not found"})
			return
		}
		depth = parent.Depth + 1
		path = parent.Path + "." + input.Slug
	} else {
		depth = 0
		path = input.Slug
	}

	group := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ParentID:    input.ParentID,
		Slug:        input.Slug,
		Name:        input.Name,
		Description: input.Description,
		Depth:       depth,
		Path:        path,
	}

	if err := s.db.CreateGroup(c.Request.Context(), group); err != nil {
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

	var input struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Name != nil {
		group.Name = *input.Name
	}
	if input.Description != nil {
		group.Description = *input.Description
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

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	if err := s.db.DeleteGroup(c.Request.Context(), groupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group deleted"})
}

func (s *Server) getGroupPermissions(c *gin.Context) {
	groupID := c.Param("group_id")
	perms, err := s.db.GetGroupPermissions(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if perms == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "permissions not found"})
		return
	}
	c.JSON(http.StatusOK, perms)
}

func (s *Server) setGroupPermissions(c *gin.Context) {
	groupID := c.Param("group_id")

	var input struct {
		AllowMethods      []string            `json:"allow_methods"`
		AllowContracts    []string            `json:"allow_contracts"`
		OwnedContracts    []string            `json:"owned_contracts"`
		ContractFunctions map[string][]string `json:"contract_functions"` // contract_address -> allowed function selectors
		RateLimitRPS      *int                `json:"rate_limit_rps"`
		RateLimitDaily    *int                `json:"rate_limit_daily"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	perms := &rbac.GroupPermissions{
		ID:                uuid.New().String(),
		GroupID:           groupID,
		AllowMethods:      input.AllowMethods,
		AllowContracts:    input.AllowContracts,
		OwnedContracts:    input.OwnedContracts,
		ContractFunctions: input.ContractFunctions,
		RateLimitRPS:      input.RateLimitRPS,
		RateLimitDaily:    input.RateLimitDaily,
	}

	if err := s.db.SetGroupPermissions(c.Request.Context(), perms); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for group members
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	c.JSON(http.StatusOK, perms)
}

// Role handlers

func (s *Server) listRoles(c *gin.Context) {
	orgID := c.Param("org_id")
	roles, err := s.db.ListRoles(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, roles)
}

func (s *Server) createRole(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		Name        string       `json:"name" binding:"required"`
		Description string       `json:"description"`
		Claims      []rbac.Claim `json:"claims"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role := &rbac.Role{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		Name:        input.Name,
		Description: input.Description,
		Claims:      input.Claims,
	}

	if err := s.db.CreateRole(c.Request.Context(), role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, role)
}

func (s *Server) getRole(c *gin.Context) {
	roleID := c.Param("role_id")
	role, err := s.db.GetRole(c.Request.Context(), roleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if role == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	c.JSON(http.StatusOK, role)
}

func (s *Server) updateRole(c *gin.Context) {
	roleID := c.Param("role_id")

	role, err := s.db.GetRole(c.Request.Context(), roleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if role == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	var input struct {
		Name        *string       `json:"name"`
		Description *string       `json:"description"`
		Claims      *[]rbac.Claim `json:"claims"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Name != nil {
		role.Name = *input.Name
	}
	if input.Description != nil {
		role.Description = *input.Description
	}
	if input.Claims != nil {
		role.Claims = *input.Claims
	}

	if err := s.db.UpdateRole(c.Request.Context(), role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for org
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), role.OrgID)

	c.JSON(http.StatusOK, role)
}

func (s *Server) deleteRole(c *gin.Context) {
	roleID := c.Param("role_id")

	role, err := s.db.GetRole(c.Request.Context(), roleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if role != nil {
		// Invalidate cache before deleting
		s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), role.OrgID)
	}

	if err := s.db.DeleteRole(c.Request.Context(), roleID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role deleted"})
}

// User handlers

func (s *Server) listRBACUsers(c *gin.Context) {
	limit := 100
	offset := 0
	// Parse query params if provided
	if l := c.Query("limit"); l != "" {
		if _, err := c.GetQuery("limit"); err {
			limit = 100
		}
	}

	users, err := s.db.ListUsers(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (s *Server) getRBACUser(c *gin.Context) {
	userID := c.Param("user_id")
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (s *Server) updateRBACUser(c *gin.Context) {
	userID := c.Param("user_id")

	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
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

	if err := s.db.UpdateUser(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for user
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	c.JSON(http.StatusOK, user)
}

// Membership handlers

func (s *Server) listUserMemberships(c *gin.Context) {
	userID := c.Param("user_id")
	memberships, err := s.db.ListUserMemberships(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, memberships)
}

func (s *Server) createUserMembership(c *gin.Context) {
	userID := c.Param("user_id")

	var input struct {
		GroupID string  `json:"group_id" binding:"required"`
		RoleID  *string `json:"role_id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: input.GroupID,
		RoleID:  input.RoleID,
		Source:  rbac.MembershipSourceAdmin,
	}

	if err := s.db.CreateMembership(c.Request.Context(), membership); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for user
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	c.JSON(http.StatusCreated, membership)
}

func (s *Server) deleteUserMembership(c *gin.Context) {
	userID := c.Param("user_id")
	membershipID := c.Param("membership_id")

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	if err := s.db.DeleteMembership(c.Request.Context(), membershipID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "membership deleted"})
}

// Contract ownership handlers

func (s *Server) listContractOwnerships(c *gin.Context) {
	orgID := c.Param("org_id")
	ownerships, err := s.db.ListContractOwnerships(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ownerships)
}

func (s *Server) createContractOwnership(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		ContractAddress string         `json:"contract_address" binding:"required"`
		OwnerGroupID    string         `json:"owner_group_id" binding:"required"`
		OwnerAbilities  []string       `json:"owner_abilities"`
		Metadata        map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ownership := &rbac.ContractOwnership{
		ID:              uuid.New().String(),
		ContractAddress: input.ContractAddress,
		OrgID:           orgID,
		OwnerGroupID:    input.OwnerGroupID,
		OwnerAbilities:  input.OwnerAbilities,
		Metadata:        input.Metadata,
	}
	if ownership.Metadata == nil {
		ownership.Metadata = make(map[string]any)
	}

	if err := s.db.CreateContractOwnership(c.Request.Context(), ownership); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for the owner group
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), input.OwnerGroupID)

	c.JSON(http.StatusCreated, ownership)
}

func (s *Server) updateContractOwnership(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	ownership, err := s.db.GetContractOwnershipByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ownership == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract ownership not found"})
		return
	}

	var input struct {
		OwnerGroupID   *string        `json:"owner_group_id"`
		OwnerAbilities []string       `json:"owner_abilities"`
		Metadata       map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	oldGroupID := ownership.OwnerGroupID

	if input.OwnerGroupID != nil {
		ownership.OwnerGroupID = *input.OwnerGroupID
	}
	if input.OwnerAbilities != nil {
		ownership.OwnerAbilities = input.OwnerAbilities
	}
	if input.Metadata != nil {
		ownership.Metadata = input.Metadata
	}

	if err := s.db.UpdateContractOwnership(c.Request.Context(), ownership); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for both old and new owner groups
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), oldGroupID)
	if input.OwnerGroupID != nil && *input.OwnerGroupID != oldGroupID {
		s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), *input.OwnerGroupID)
	}

	c.JSON(http.StatusOK, ownership)
}

func (s *Server) deleteContractOwnership(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	ownership, err := s.db.GetContractOwnershipByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ownership == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract ownership not found"})
		return
	}

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), ownership.OwnerGroupID)

	if err := s.db.DeleteContractOwnership(c.Request.Context(), ownership.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "contract ownership deleted"})
}

// Debugging handlers

func (s *Server) getEffectivePermissions(c *gin.Context) {
	userID := c.Param("user_id")
	orgSlug := c.Query("org")

	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	perms, err := s.rbacAccessCtrl.GetEffectivePermissions(c.Request.Context(), user.ExternalID, orgSlug)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, perms)
}

func (s *Server) checkAccessAPI(c *gin.Context) {
	var req rbac.AccessCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (s *Server) getCacheStats(c *gin.Context) {
	stats := s.rbacAccessCtrl.CacheStats()
	c.JSON(http.StatusOK, stats)
}
