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

func (s *Server) listRBACUsers(c *gin.Context) {
	limit, offset := parsePaginationParams(c, 50)

	// Parse filter params
	orgID := c.Query("org_id")
	search := c.Query("search")

	var users []*rbac.User
	var total int
	var err error

	// Use filtered query if any filters are provided
	if orgID != "" || search != "" {
		filter := db.UserFilter{
			OrgID:  orgID,
			Search: search,
		}
		users, total, err = s.db.ListUsersFilteredPaginated(c.Request.Context(), filter, limit, offset)
	} else {
		users, total, err = s.db.ListUsersPaginated(c.Request.Context(), limit, offset)
	}

	if err != nil {
		slog.Error("failed to list users", "error", err)
		respondInternalError(c, "request failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) getRBACUser(c *gin.Context) {
	userID := c.Param("user_id")
	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("failed to get user", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to get user", "error", err)
		respondInternalError(c, "request failed")
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
		respondBadRequest(c, "invalid request body")
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
		slog.Error("failed to update user", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to get user", "error", err)
		respondInternalError(c, "request failed")
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Get linked ETH addresses
	links, err := s.db.GetEthAddressesByDID(c.Request.Context(), user.ExternalID)
	if err != nil {
		slog.Error("failed to get linked addresses", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to get user", "error", err)
		respondInternalError(c, "request failed")
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Delete all memberships for this user first
	memberships, err := s.db.ListUserMemberships(c.Request.Context(), userID)
	if err != nil {
		slog.Error("failed to list user memberships", "error", err)
		respondInternalError(c, "request failed")
		return
	}
	for _, membership := range memberships {
		if err := s.db.DeleteMembership(c.Request.Context(), membership.ID); err != nil {
			slog.Error("failed to delete membership", "membership_id", membership.ID, "error", err)
			respondInternalError(c, "request failed")
			return
		}
	}

	// Delete the user
	if err := s.db.DeleteUser(c.Request.Context(), userID); err != nil {
		slog.Error("failed to delete user", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to list user memberships", "error", err)
		respondInternalError(c, "request failed")
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
		respondBadRequest(c, "invalid request body")
		return
	}

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: input.GroupID,
		Source:  rbac.MembershipSourceAdmin,
	}

	if err := s.db.CreateMembership(c.Request.Context(), membership); err != nil {
		slog.Error("failed to create membership", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to delete membership", "error", err)
		respondInternalError(c, "request failed")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "membership deleted"})
}

// Debugging handlers

func (s *Server) getEffectivePermissions(c *gin.Context) {
	userID := c.Param("user_id")

	user, err := s.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("failed to get user", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to get effective permissions", "error", err)
		respondInternalError(c, "request failed")
		return
	}

	c.JSON(http.StatusOK, perms)
}

func (s *Server) checkAccessAPI(c *gin.Context) {
	var req rbac.AccessCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequest(c, "invalid request body")
		return
	}

	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), &req)
	if err != nil {
		slog.Error("failed to check access", "error", err)
		respondInternalError(c, "request failed")
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
		slog.Error("failed to get address collisions", "error", err)
		respondInternalError(c, "request failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"collisions": collisions, "count": len(collisions)})
}
