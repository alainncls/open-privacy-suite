package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/proxy"
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
		// Check for unique constraint violation (duplicate address in org)
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "contract with this address already exists in this organization"})
			return
		}
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

// ContractSyncStatus represents the on-chain status of a contract
type ContractSyncStatus struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Status  string `json:"status"` // "exists", "missing", "error"
	Error   string `json:"error,omitempty"`
}

// checkContractsOnChain checks all contracts against the chain and returns their status.
// POST /orgs/:org_id/contracts/sync-check
func (s *Server) checkContractsOnChain(c *gin.Context) {
	orgID := c.Param("org_id")

	contracts, err := s.db.ListContracts(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if len(contracts) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"total":    0,
			"existing": []ContractSyncStatus{},
			"missing":  []ContractSyncStatus{},
			"errors":   []ContractSyncStatus{},
		})
		return
	}

	var existing, missing, errors []ContractSyncStatus

	for _, contract := range contracts {
		status := ContractSyncStatus{
			ID:      contract.ID,
			Address: contract.Address,
			Name:    contract.Name,
		}

		// Make eth_getCode RPC call
		code, err := s.getContractCode(contract.Address)
		if err != nil {
			// RPC error - could be chain unavailable
			status.Status = "error"
			status.Error = err.Error()
			errors = append(errors, status)
			continue
		}

		// Check if contract exists on chain
		// eth_getCode returns "0x" for addresses with no code
		if code == "0x" || code == "" {
			status.Status = "missing"
			missing = append(missing, status)
		} else {
			status.Status = "exists"
			existing = append(existing, status)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":    len(contracts),
		"existing": existing,
		"missing":  missing,
		"errors":   errors,
	})
}

// deleteStaleContracts deletes contracts that are confirmed to be missing on-chain.
// POST /orgs/:org_id/contracts/sync-delete
func (s *Server) deleteStaleContracts(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		ContractIDs []string `json:"contract_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(input.ContractIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no contract IDs provided"})
		return
	}

	// Verify all contracts belong to this org and re-check they're still missing
	var deleted []string
	var skipped []struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}

	for _, contractID := range input.ContractIDs {
		contract, err := s.db.GetContract(c.Request.Context(), contractID)
		if err != nil {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "database error: " + err.Error()})
			continue
		}
		if contract == nil {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "contract not found"})
			continue
		}
		if contract.OrgID != orgID {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "contract belongs to different organization"})
			continue
		}

		// Re-verify the contract is still missing on-chain (safety check)
		code, err := s.getContractCode(contract.Address)
		if err != nil {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "chain unavailable: " + err.Error()})
			continue
		}
		if code != "0x" && code != "" {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "contract now exists on chain"})
			continue
		}

		// Delete the contract
		if err := s.db.DeleteContract(c.Request.Context(), contractID); err != nil {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "delete failed: " + err.Error()})
			continue
		}

		deleted = append(deleted, contract.Address)
	}

	// Invalidate cache for the org if any contracts were deleted
	if len(deleted) > 0 {
		s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted_count":     len(deleted),
		"deleted_addresses": deleted,
		"skipped":           skipped,
	})
}

// getContractCode makes an eth_getCode RPC call to check if a contract exists on-chain.
// Returns the code hex string, or an error if the RPC call fails.
func (s *Server) getContractCode(address string) (string, error) {
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getCode",
		Params:  []interface{}{address, "latest"},
		ID:      1,
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", err
	}

	respBody, statusCode, err := s.proxy.Forward(reqBody)
	if err != nil {
		return "", err
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("RPC request failed with status %d", statusCode)
	}

	var rpcResp proxy.JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", err
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Result should be a hex string
	code, ok := rpcResp.Result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected response type from eth_getCode")
	}

	return code, nil
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
