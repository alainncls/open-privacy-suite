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

	var input struct {
		Factory    string `json:"factory" binding:"required"`
		SaltPrefix string `json:"salt_prefix" binding:"required"`
		Count      int    `json:"count" binding:"required,min=1,max=100"`
		Note       string `json:"note"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate factory address
	if !auth.IsValidAddress(input.Factory) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid factory address format"})
		return
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
			ID:      uuid.New().String(),
			OrgID:   orgID,
			Address: strings.ToLower(gen.Address.Hex()),
			Factory: strings.ToLower(input.Factory),
			Salt:    gen.Salt[:],
			Note:    input.Note,
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
			ID:        addr.ID,
			OrgID:     addr.OrgID,
			Address:   addr.Address,
			Factory:   addr.Factory,
			Salt:      "0x" + hex.EncodeToString(addr.Salt),
			Note:      addr.Note,
			CreatedAt: addr.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	c.JSON(http.StatusCreated, gin.H{"addresses": response})
}

// listPreregisteredAddresses handles GET /orgs/:org_id/addresses/preregistered
func (s *Server) listPreregisteredAddresses(c *gin.Context) {
	orgID := c.Param("org_id")

	addresses, err := s.db.ListPreregisteredAddresses(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert to response format
	response := make([]preregisteredAddressResponse, len(addresses))
	for i, addr := range addresses {
		resp := preregisteredAddressResponse{
			ID:        addr.ID,
			OrgID:     addr.OrgID,
			Address:   addr.Address,
			Factory:   addr.Factory,
			Salt:      "0x" + hex.EncodeToString(addr.Salt),
			Note:      addr.Note,
			CreatedAt: addr.CreatedAt.Format("2006-01-02T15:04:05Z"),
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

	// URL-decode the address (in case it was encoded)
	address = strings.TrimSpace(address)

	// Validate address format
	if !auth.IsValidAddress(address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}

	err := s.db.DeletePreregisteredAddress(c.Request.Context(), orgID, address)
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
	ID        string  `json:"id"`
	OrgID     string  `json:"org_id"`
	Address   string  `json:"address"`
	Factory   string  `json:"factory"`
	Salt      string  `json:"salt"` // Hex-encoded
	Note      string  `json:"note,omitempty"`
	CreatedAt string  `json:"created_at"`
	UsedAt    *string `json:"used_at,omitempty"`
}
