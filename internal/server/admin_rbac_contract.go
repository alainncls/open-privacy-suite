package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"
)

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
