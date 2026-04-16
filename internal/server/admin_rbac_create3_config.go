package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/auth"
)

// getOrgCreate3Config handles GET /orgs/:org_id/config/create3
// Returns the configured CREATE3 factory address for the organization
func (s *Server) getOrgCreate3Config(c *gin.Context) {
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

	// Get factory from org settings
	var factory string
	if org.Settings != nil {
		if f, ok := org.Settings["factory_address"].(string); ok {
			factory = f
		}
	}

	if factory == "" {
		c.JSON(http.StatusOK, gin.H{
			"factory":    "",
			"configured": false,
			"message":    "No CREATE3 factory configured for this organization.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"factory":    factory,
		"configured": true,
	})
}

// setOrgCreate3Config handles PUT /orgs/:org_id/config/create3
// Sets the CREATE3 factory address for the organization
func (s *Server) setOrgCreate3Config(c *gin.Context) {
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
		Factory string `json:"factory" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate factory address format
	if !auth.IsValidAddress(input.Factory) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid factory address format"})
		return
	}

	// Update org settings
	if org.Settings == nil {
		org.Settings = make(map[string]any)
	}
	org.Settings["factory_address"] = strings.ToLower(input.Factory)

	if err := s.db.UpdateOrganization(c.Request.Context(), org); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"factory":    org.Settings["factory_address"],
		"configured": true,
	})
}
