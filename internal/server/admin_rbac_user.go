package server

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// User handlers

func (s *Server) listRBACUsers(c *gin.Context) {
	limit := 100
	offset := 0
	// Parse query params if provided
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
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

	// Invalidate cache for this user
	s.rbacAccessCtrl.InvalidateUser(c.Request.Context(), user.ID)

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

	c.JSON(http.StatusOK, links)
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
