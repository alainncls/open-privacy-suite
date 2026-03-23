package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
)

// Contract handlers

func (s *Server) listContracts(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := parsePaginationParams(c, 50)

	filter := db.ContractListFilter{
		Search: c.Query("search"),
	}

	contracts, total, err := s.db.ListContractsFiltered(c.Request.Context(), orgID, limit, offset, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": contracts, "total": total, "limit": limit, "offset": offset})
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

// updateContractABI updates the ABI for a contract.
// PUT /orgs/:org_id/contracts/:address/abi
func (s *Server) updateContractABI(c *gin.Context) {
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
		ABI string `json:"abi" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate ABI is a valid JSON array
	if input.ABI != "" && !strings.HasPrefix(strings.TrimSpace(input.ABI), "[") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "abi must be a valid JSON array"})
		return
	}

	// Validate it's valid JSON
	var abiItems []json.RawMessage
	if err := json.Unmarshal([]byte(input.ABI), &abiItems); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "abi must be valid JSON: " + err.Error()})
		return
	}

	if err := s.db.UpdateContractABI(c.Request.Context(), contract.ID, input.ABI); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return updated contract
	contract.ABI = input.ABI
	c.JSON(http.StatusOK, contract)
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
		GroupID   string              `json:"group_id" binding:"required"`
		Functions []rbac.FunctionRule `json:"functions"` // nil = all functions
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
		Functions json.RawMessage `json:"functions"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// input.Functions is nil when the key is absent from the JSON body (no change).
	// input.Functions is "null" when explicitly set to null (all functions allowed).
	// input.Functions is "[...]" when set to an array of function rules.
	if input.Functions != nil {
		if string(input.Functions) == "null" {
			grant.Functions = nil
		} else {
			var rules []rbac.FunctionRule
			if err := json.Unmarshal(input.Functions, &rules); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid functions format"})
				return
			}
			grant.Functions = rules
		}
	}

	if err := s.db.UpdateContractGrant(c.Request.Context(), grant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache for the group
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	c.JSON(http.StatusOK, grant)
}

// lookupContractByAddress looks up a contract by address globally and returns
// the contract info, its organization, and all grants with group+access details.
// GET /contracts/by-address/:address
func (s *Server) lookupContractByAddress(c *gin.Context) {
	address := c.Param("address")

	contract, err := s.db.GetContractByAddressGlobal(c.Request.Context(), address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	// Get the organization
	org, err := s.db.GetOrganization(c.Request.Context(), contract.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get grants for this contract
	grants, err := s.db.ListContractGrantsByContract(c.Request.Context(), contract.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Build grants with group+access info
	type grantInfo struct {
		Grant  *rbac.ContractGrant `json:"grant"`
		Group  *rbac.Group         `json:"group"`
		Access *rbac.GroupAccess   `json:"access"`
	}

	grantInfos := make([]grantInfo, 0, len(grants))
	for _, grant := range grants {
		group, err := s.db.GetGroup(c.Request.Context(), grant.GroupID)
		if err != nil || group == nil {
			continue
		}
		access, _ := s.db.GetGroupAccess(c.Request.Context(), grant.GroupID)
		grantInfos = append(grantInfos, grantInfo{
			Grant:  grant,
			Group:  group,
			Access: access,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"contract":     contract,
		"organization": org,
		"grants":       grantInfos,
	})
}

// getContractGrantSummary returns grant counts and group names for all contracts in an org.
// GET /orgs/:org_id/contracts/grant-summary
func (s *Server) getContractGrantSummary(c *gin.Context) {
	orgID := c.Param("org_id")
	summary, err := s.db.GetContractGrantSummary(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, summary)
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

// batchMoveContracts moves contracts from auto-created groups to a target group.
// POST /orgs/:org_id/contracts/batch-move
func (s *Server) batchMoveContracts(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		ContractIDs            []string `json:"contract_ids" binding:"required"`
		TargetGroupID          string   `json:"target_group_id"`
		NewGroup               *struct {
			Slug string `json:"slug" binding:"required"`
			Name string `json:"name" binding:"required"`
		} `json:"new_group"`
		DeleteEmptyAutoGroups bool `json:"delete_empty_auto_groups"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(input.ContractIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract_ids is required"})
		return
	}
	if len(input.ContractIDs) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many contract_ids (max 200)"})
		return
	}
	if input.TargetGroupID == "" && input.NewGroup == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "either target_group_id or new_group is required"})
		return
	}
	if input.TargetGroupID != "" && input.NewGroup != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot specify both target_group_id and new_group"})
		return
	}

	type moveResult struct {
		TargetGroupID     string   `json:"target_group_id"`
		MovedCount        int      `json:"moved_count"`
		DeletedGroupIDs   []string `json:"deleted_group_ids,omitempty"`
	}

	var result moveResult

	err := s.db.WithTx(c.Request.Context(), func(tx *db.Tx) error {
		ctx := c.Request.Context()

		// Resolve target group
		targetGroupID := input.TargetGroupID
		if input.NewGroup != nil {
			// Create new group inline with deploy claims
			newGroup := &rbac.Group{
				ID:    uuid.New().String(),
				OrgID: orgID,
				Slug:  input.NewGroup.Slug,
				Name:  input.NewGroup.Name,
				Depth: 0,
				Path:  input.NewGroup.Slug,
			}
			if err := tx.CreateGroup(ctx, newGroup); err != nil {
				if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
					return fmt.Errorf("group with slug '%s' already exists", input.NewGroup.Slug)
				}
				return fmt.Errorf("failed to create group: %w", err)
			}
			// Create group access with deploy claims
			claims := rbac.ExpandClaims([]rbac.Claim{rbac.ClaimDeploy})
			if err := tx.CreateGroupAccess(ctx, &rbac.GroupAccess{
				ID:             uuid.New().String(),
				GroupID:        newGroup.ID,
				AllowedMethods: []string{"*"},
				Claims:         claims,
			}); err != nil {
				return fmt.Errorf("failed to create group access: %w", err)
			}
			targetGroupID = newGroup.ID
		} else {
			// Verify target group exists and belongs to org
			group, err := tx.GetGroup(ctx, targetGroupID)
			if err != nil {
				return fmt.Errorf("failed to get target group: %w", err)
			}
			if group == nil || group.OrgID != orgID {
				return fmt.Errorf("target group not found in this organization")
			}
		}

		result.TargetGroupID = targetGroupID

		// Verify all contracts belong to this org
		contracts, err := tx.GetContractsByIDs(ctx, input.ContractIDs)
		if err != nil {
			return fmt.Errorf("failed to get contracts: %w", err)
		}
		for _, cid := range input.ContractIDs {
			contract, ok := contracts[cid]
			if !ok {
				return fmt.Errorf("contract %s not found", cid)
			}
			if contract.OrgID != orgID {
				return fmt.Errorf("contract %s does not belong to this organization", cid)
			}
		}

		// Collect auto-created source group IDs across selected contracts
		autoGroupIDs, err := tx.GetAutoCreatedGroupIDsForContracts(ctx, input.ContractIDs)
		if err != nil {
			return fmt.Errorf("failed to get auto-created groups: %w", err)
		}

		// For each contract: create grant to target, remove grants to auto-created groups
		for _, cid := range input.ContractIDs {
			// Create grant to target group (ignore if already exists)
			if err := tx.CreateContractGrantIfNotExists(ctx, &rbac.ContractGrant{
				ID:         uuid.New().String(),
				ContractID: cid,
				GroupID:    targetGroupID,
			}); err != nil {
				return fmt.Errorf("failed to create grant for contract %s: %w", cid, err)
			}

			// Delete only grants to auto-created source groups (preserves manual grants)
			if err := tx.DeleteContractGrantsByContractAndGroups(ctx, cid, autoGroupIDs); err != nil {
				return fmt.Errorf("failed to remove auto grants for contract %s: %w", cid, err)
			}

			result.MovedCount++
		}

		// Optionally delete empty auto-created groups
		if input.DeleteEmptyAutoGroups && len(autoGroupIDs) > 0 {
			for _, gid := range autoGroupIDs {
				count, err := tx.CountContractGrantsByGroup(ctx, gid)
				if err != nil {
					return fmt.Errorf("failed to count grants for group %s: %w", gid, err)
				}
				if count == 0 {
					if err := tx.DeleteGroupWithDependenciesTx(ctx, gid); err != nil {
						return fmt.Errorf("failed to delete empty group %s: %w", gid, err)
					}
					result.DeletedGroupIDs = append(result.DeletedGroupIDs, gid)
				}
			}
		}

		// Invalidate org cache
		if err := tx.InvalidateCacheForOrg(ctx, orgID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}

		return nil
	})

	if err != nil {
		// Distinguish validation errors from internal errors
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "does not belong") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
