package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
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

	// Group Access (replaces old permissions and roles)
	api.GET("/orgs/:org_id/groups/:group_id/access", s.getGroupAccess)
	api.PUT("/orgs/:org_id/groups/:group_id/access", s.setGroupAccess)

	// Contracts
	api.GET("/orgs/:org_id/contracts", s.listContracts)
	api.POST("/orgs/:org_id/contracts", s.createContract)
	api.GET("/orgs/:org_id/contracts/:address", s.getContract)
	api.PUT("/orgs/:org_id/contracts/:address", s.updateContract)
	api.DELETE("/orgs/:org_id/contracts/:address", s.deleteContract)

	// Contract Grants
	api.GET("/orgs/:org_id/contracts/:address/grants", s.listContractGrants)
	api.POST("/orgs/:org_id/contracts/:address/grants", s.createContractGrant)
	api.PUT("/orgs/:org_id/contracts/:address/grants/:group_id", s.updateContractGrant)
	api.DELETE("/orgs/:org_id/contracts/:address/grants/:group_id", s.deleteContractGrant)

	// Users
	api.GET("/users", s.listRBACUsers)
	api.GET("/users/:user_id", s.getRBACUser)
	api.PUT("/users/:user_id", s.updateRBACUser)
	api.GET("/users/:user_id/linked-addresses", s.getUserLinkedAddresses)

	// Memberships
	api.GET("/users/:user_id/memberships", s.listUserMemberships)
	api.POST("/users/:user_id/memberships", s.createUserMembership)
	api.DELETE("/users/:user_id/memberships/:membership_id", s.deleteUserMembership)

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
		IsOrgAdmin  bool    `json:"is_org_admin"`
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
		IsOrgAdmin:  input.IsOrgAdmin,
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
		IsOrgAdmin  *bool   `json:"is_org_admin"`
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
	if input.IsOrgAdmin != nil {
		group.IsOrgAdmin = *input.IsOrgAdmin
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

// Group Access handlers (replaces old permissions)

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
			DefaultClaims:  []rbac.Claim{},
		}
	}
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

	var input struct {
		AllowedMethods []string     `json:"allowed_methods"`
		DefaultClaims  []rbac.Claim `json:"default_claims"`
		RateLimitRPS   *int         `json:"rate_limit_rps"`
		RateLimitDaily *int         `json:"rate_limit_daily"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if access already exists
	existing, err := s.db.GetGroupAccess(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	access := &rbac.GroupAccess{
		GroupID:        groupID,
		AllowedMethods: input.AllowedMethods,
		DefaultClaims:  input.DefaultClaims,
		RateLimitRPS:   input.RateLimitRPS,
		RateLimitDaily: input.RateLimitDaily,
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

	c.JSON(http.StatusOK, access)
}

// Contract handlers

func (s *Server) listContracts(c *gin.Context) {
	orgID := c.Param("org_id")
	contracts, err := s.db.ListContracts(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, contracts)
}

func (s *Server) createContract(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		Address  string         `json:"address" binding:"required"`
		Name     string         `json:"name"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate Ethereum address format
	if !auth.IsValidAddress(input.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Ethereum address format"})
		return
	}

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  strings.ToLower(input.Address),
		Name:     input.Name,
		Metadata: input.Metadata,
	}
	if contract.Metadata == nil {
		contract.Metadata = make(map[string]any)
	}

	if err := s.db.CreateContract(c.Request.Context(), contract); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, contract)
}

func (s *Server) getContract(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}
	c.JSON(http.StatusOK, contract)
}

func (s *Server) updateContract(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		Name     *string        `json:"name"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Name != nil {
		contract.Name = *input.Name
	}
	if input.Metadata != nil {
		contract.Metadata = input.Metadata
	}

	if err := s.db.UpdateContract(c.Request.Context(), contract); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, contract)
}

func (s *Server) deleteContract(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	// Invalidate cache for the entire org (grants may affect many groups)
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	if err := s.db.DeleteContract(c.Request.Context(), contract.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "contract deleted"})
}

// Contract Grant handlers

func (s *Server) listContractGrants(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	grants, err := s.db.ListContractGrantsByContract(c.Request.Context(), contract.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, grants)
}

func (s *Server) createContractGrant(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		GroupID   string       `json:"group_id" binding:"required"`
		Claims    []rbac.Claim `json:"claims" binding:"required"`
		Functions []string     `json:"functions"` // nil = all functions
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify group exists and belongs to the same org
	group, err := s.db.GetGroup(c.Request.Context(), input.GroupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if group == nil || group.OrgID != orgID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group not found or belongs to different organization"})
		return
	}

	grant := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    input.GroupID,
		Claims:     input.Claims,
		Functions:  input.Functions,
	}

	if err := s.db.CreateContractGrant(c.Request.Context(), grant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for the group
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), input.GroupID)

	c.JSON(http.StatusCreated, grant)
}

func (s *Server) updateContractGrant(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")
	groupID := c.Param("group_id")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	grant, err := s.db.GetContractGrantByContractAndGroup(c.Request.Context(), contract.ID, groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if grant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
		return
	}

	var input struct {
		Claims    *[]rbac.Claim `json:"claims"`
		Functions *[]string     `json:"functions"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Claims != nil {
		grant.Claims = *input.Claims
	}
	if input.Functions != nil {
		grant.Functions = *input.Functions
	}

	if err := s.db.UpdateContractGrant(c.Request.Context(), grant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for the group
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	c.JSON(http.StatusOK, grant)
}

func (s *Server) deleteContractGrant(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")
	groupID := c.Param("group_id")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	grant, err := s.db.GetContractGrantByContractAndGroup(c.Request.Context(), contract.ID, groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if grant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
		return
	}

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	if err := s.db.DeleteContractGrant(c.Request.Context(), grant.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "grant deleted"})
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

func (s *Server) getUserLinkedAddresses(c *gin.Context) {
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

	links, err := s.db.GetEthAddressesByDID(user.ExternalID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	addresses := make([]gin.H, 0, len(links))
	for _, link := range links {
		addr := gin.H{
			"address":     link.EthAddress,
			"verified_at": link.VerifiedAt,
		}
		if link.ENSName != nil {
			addr["ens_name"] = *link.ENSName
		}
		if link.ENSResolvedAt != nil {
			addr["ens_resolved_at"] = *link.ENSResolvedAt
		}
		addresses = append(addresses, addr)
	}

	c.JSON(http.StatusOK, gin.H{"addresses": addresses})
}

// Membership handlers

func (s *Server) listUserMemberships(c *gin.Context) {
	userID := c.Param("user_id")
	memberships, err := s.db.ListUserMembershipsWithDetails(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Return empty array instead of null if no memberships
	if memberships == nil {
		memberships = []*rbac.MembershipWithDetails{}
	}
	c.JSON(http.StatusOK, memberships)
}

func (s *Server) createUserMembership(c *gin.Context) {
	userID := c.Param("user_id")

	var input struct {
		GroupID string `json:"group_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: input.GroupID,
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
