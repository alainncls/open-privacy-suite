package server

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// Organization handlers

func (s *Server) listOrganizations(c *gin.Context) {
	orgs, err := s.db.ListOrganizations(c.Request.Context())
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	respondOK(c, orgs)
}

func (s *Server) createOrganization(c *gin.Context) {
	var input struct {
		Slug     string         `json:"slug" binding:"required"`
		Name     string         `json:"name" binding:"required"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, err.Error())
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
		respondInternalError(c, err.Error())
		return
	}

	respondCreated(c, org)
}

func (s *Server) getOrganization(c *gin.Context) {
	orgID := c.Param("org_id")
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	respondOK(c, org)
}

func (s *Server) updateOrganization(c *gin.Context) {
	orgID := c.Param("org_id")

	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}

	var input struct {
		Slug     *string        `json:"slug"`
		Name     *string        `json:"name"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, err.Error())
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
		respondInternalError(c, err.Error())
		return
	}

	respondOK(c, org)
}

func (s *Server) deleteOrganization(c *gin.Context) {
	orgID := c.Param("org_id")

	// Prevent deleting the default organization
	if orgID == rbac.DefaultOrgID {
		respondBadRequest(c, "cannot delete the default organization")
		return
	}

	// Check if organization exists
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}

	// Delete the organization (cascades to groups, contracts, etc. via DB constraints)
	if err := s.db.DeleteOrganization(c.Request.Context(), orgID); err != nil {
		respondInternalError(c, err.Error())
		return
	}

	// Invalidate cache for this organization
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	respondDeleted(c, "organization")
}
