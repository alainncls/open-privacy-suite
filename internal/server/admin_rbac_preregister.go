package server

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/evm/create3"
	"privacy-proxy/internal/rbac"
)

// Preregistered Address handlers

// preregisterAddresses handles POST /orgs/:org_id/addresses/preregister
// It generates CREATE3 addresses and preregisters them for the organization.
func (s *Server) preregisterAddresses(c *gin.Context) {
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
		Factory        string `json:"factory" binding:"required"`
		SaltPrefix     string `json:"salt_prefix" binding:"required"`
		Count          int    `json:"count" binding:"required,min=1,max=100"`
		Note           string `json:"note"`
		ConstructorABI string `json:"constructor_abi"` // Contract ABI JSON for constructor arg validation
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

	// Validate factory matches org's configured factory (security: per-org isolation)
	inputFactory := strings.ToLower(input.Factory)
	if org.Settings != nil {
		if configuredFactory, ok := org.Settings["factory_address"].(string); ok && configuredFactory != "" {
			if strings.ToLower(configuredFactory) != inputFactory {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "factory address does not match organization's configured factory",
				})
				return
			}
		}
	}

	// If org doesn't have a factory configured yet, set it from this request
	if org.Settings == nil || org.Settings["factory_address"] == nil || org.Settings["factory_address"] == "" {
		if org.Settings == nil {
			org.Settings = make(map[string]any)
		}
		org.Settings["factory_address"] = inputFactory
		if err := s.db.UpdateOrganization(c.Request.Context(), org); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save factory configuration: " + err.Error()})
			return
		}
	}

	// Generate CREATE3 addresses
	generated, err := create3.GenerateAddressPoolFromHex(input.Factory, input.SaltPrefix, input.Count)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert to PreregisteredAddress models
	addresses := make([]*rbac.PreregisteredAddress, len(generated))
	for i, gen := range generated {
		addresses[i] = &rbac.PreregisteredAddress{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			Address:        strings.ToLower(gen.Address.Hex()),
			Factory:        strings.ToLower(input.Factory),
			Salt:           gen.Salt[:],
			Note:           input.Note,
			ConstructorABI: input.ConstructorABI,
		}
	}

	// Store in database
	if err := s.db.CreatePreregisteredAddresses(c.Request.Context(), addresses); err != nil {
		// Check for unique constraint violation
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "one or more addresses already registered"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return the created addresses with salt as hex string
	response := make([]preregisteredAddressResponse, len(addresses))
	for i, addr := range addresses {
		response[i] = preregisteredAddressResponse{
			ID:             addr.ID,
			OrgID:          addr.OrgID,
			Address:        addr.Address,
			Factory:        addr.Factory,
			Salt:           "0x" + hex.EncodeToString(addr.Salt),
			Note:           addr.Note,
			ConstructorABI: addr.ConstructorABI,
			CreatedAt:      addr.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	c.JSON(http.StatusCreated, gin.H{"addresses": response})
}

// listPreregisteredAddresses handles GET /orgs/:org_id/addresses/preregistered
func (s *Server) listPreregisteredAddresses(c *gin.Context) {
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

	addresses, err := s.db.ListPreregisteredAddresses(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert to response format
	response := make([]preregisteredAddressResponse, len(addresses))
	for i, addr := range addresses {
		resp := preregisteredAddressResponse{
			ID:             addr.ID,
			OrgID:          addr.OrgID,
			Address:        addr.Address,
			Factory:        addr.Factory,
			Salt:           "0x" + hex.EncodeToString(addr.Salt),
			Note:           addr.Note,
			ConstructorABI: addr.ConstructorABI,
			CreatedAt:      addr.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if addr.UsedAt != nil {
			usedAt := addr.UsedAt.Format("2006-01-02T15:04:05Z")
			resp.UsedAt = &usedAt
		}
		response[i] = resp
	}

	c.JSON(http.StatusOK, response)
}

// deletePreregisteredAddress handles DELETE /orgs/:org_id/addresses/preregistered/:address
func (s *Server) deletePreregisteredAddress(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

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

	// URL-decode the address (in case it was encoded)
	address = strings.TrimSpace(address)

	// Validate address format
	if !auth.IsValidAddress(address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}

	err = s.db.DeletePreregisteredAddress(c.Request.Context(), orgID, address)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "preregistered address not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "preregistered address deleted"})
}

// preregisteredAddressResponse is the JSON response format for preregistered addresses.
type preregisteredAddressResponse struct {
	ID             string  `json:"id"`
	OrgID          string  `json:"org_id"`
	Address        string  `json:"address"`
	Factory        string  `json:"factory"`
	Salt           string  `json:"salt"` // Hex-encoded
	Note           string  `json:"note,omitempty"`
	ConstructorABI string  `json:"constructor_abi,omitempty"` // Contract ABI JSON
	CreatedAt      string  `json:"created_at"`
	UsedAt         *string `json:"used_at,omitempty"`
}

// updatePreregisteredAddressABI handles PUT /orgs/:org_id/addresses/preregistered/:address/abi
// It updates the constructor ABI for an existing preregistered address.
func (s *Server) updatePreregisteredAddressABI(c *gin.Context) {
	orgID := c.Param("org_id")
	address := c.Param("address")

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

	// Validate address format
	address = strings.TrimSpace(address)
	if !auth.IsValidAddress(address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}

	var input struct {
		ConstructorABI string `json:"constructor_abi" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the ABI is valid JSON (basic check)
	if input.ConstructorABI != "" && !strings.HasPrefix(strings.TrimSpace(input.ConstructorABI), "[") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "constructor_abi must be a valid JSON array"})
		return
	}

	err = s.db.UpdateConstructorABI(c.Request.Context(), orgID, address, input.ConstructorABI)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "preregistered address not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "constructor ABI updated"})
}

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
