package server

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// User handlers

// userListItem extends rbac.User with the user's group memberships for the
// list response. Memberships are scoped to the caller's accessible orgs
// for non-super-admin callers (cross-org isolation).
type userListItem struct {
	*rbac.User
	Groups []rbac.UserGroupMembership `json:"groups"`
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

	c.JSON(http.StatusOK, user)
}

func (s *Server) getUserLinkedAddresses(c *gin.Context) {
	userID := c.Param("user_id")

	// Get user to find their external ID (DID)
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
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

	// Check if user exists
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Delete all memberships for this user first
	memberships, err := s.db.ListUserMemberships(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, membership := range memberships {
		if err := s.db.DeleteMembership(c.Request.Context(), membership.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete membership: " + err.Error()})
			return
		}
	}

	// Delete the user
	if err := s.db.DeleteUser(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for this user
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), userID)

	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}

// Membership handlers

func (s *Server) listUserMemberships(c *gin.Context) {
	userID := c.Param("user_id")
	memberships, err := s.db.ListUserMembershipsWithDetails(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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

	// Invalidate cache for this user
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

	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Get org slug from query param, default to "default"
	orgSlug := c.Query("org")
	if orgSlug == "" {
		orgSlug = "default"
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

// getEthAddressCollisions lists ETH addresses linked to more than one DID.
// These may indicate intentional key sharing (e.g. shared deployer wallets)
// or a key-compromise event and should be reviewed by an administrator.
func (s *Server) getEthAddressCollisions(c *gin.Context) {
	collisions, err := s.db.GetAddressLinkCollisions(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"collisions": collisions, "count": len(collisions)})
}
