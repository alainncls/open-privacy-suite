package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

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

	// Validate slug format before database insertion
	if errMsg := validateSlug(input.Slug); errMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
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
		if parent.OrgID != orgID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "parent group does not belong to the same organization"})
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
