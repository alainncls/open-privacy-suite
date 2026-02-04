package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"
)

// registerManagedProxy handles POST /orgs/:org_id/proxies
// Registers a deployed proxy contract for upgrade management.
func (s *Server) registerManagedProxy(c *gin.Context) {
	orgID := c.Param("org_id")

	// Verify the organization exists
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
		ProxyAddress string `json:"proxy_address" binding:"required"`
		ProxyType    string `json:"proxy_type" binding:"required"` // "erc1967", "transparent", etc.
		CurrentImpl  string `json:"current_impl"`                  // Optional: current implementation address
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate proxy address format
	if !auth.IsValidAddress(input.ProxyAddress) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy address format"})
		return
	}

	// Validate implementation address if provided
	if input.CurrentImpl != "" && !auth.IsValidAddress(input.CurrentImpl) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid implementation address format"})
		return
	}

	// Validate proxy type
	validTypes := map[string]bool{
		"erc1967":     true,
		"transparent": true,
		"beacon":      true,
		"uups":        true,
	}
	proxyType := strings.ToLower(input.ProxyType)
	if !validTypes[proxyType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy type, must be: erc1967, transparent, beacon, or uups"})
		return
	}

	// Normalize addresses
	proxyAddr := strings.ToLower(input.ProxyAddress)
	if !strings.HasPrefix(proxyAddr, "0x") {
		proxyAddr = "0x" + proxyAddr
	}

	currentImpl := strings.ToLower(input.CurrentImpl)
	if currentImpl != "" && !strings.HasPrefix(currentImpl, "0x") {
		currentImpl = "0x" + currentImpl
	}

	// Create the managed proxy record
	proxy := &rbac.ManagedProxy{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ProxyAddress: proxyAddr,
		ProxyType:    proxyType,
		CurrentImpl:  currentImpl,
	}

	if err := s.db.CreateManagedProxy(c.Request.Context(), proxy); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "proxy already registered"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"proxy_address": proxyAddr,
		"proxy_type":    proxyType,
		"current_impl":  currentImpl,
		"org_id":        orgID,
	})
}

// listManagedProxies handles GET /orgs/:org_id/proxies
func (s *Server) listManagedProxies(c *gin.Context) {
	orgID := c.Param("org_id")

	// Verify the organization exists
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	proxies, err := s.db.ListManagedProxies(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, proxies)
}
