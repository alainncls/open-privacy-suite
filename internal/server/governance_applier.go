package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// ApplyGovernanceMutation executes an approved governance request.
// It implements governance.Applier.
func (s *Server) ApplyGovernanceMutation(ctx context.Context, req *rbac.ApprovalRequest) error {
	switch req.ChangeType {
	case "createContractGrant":
		return s.applyCreateContractGrant(ctx, req)
	case "updateContractGrant":
		return s.applyUpdateContractGrant(ctx, req)
	case "deleteContractGrant":
		return s.applyDeleteContractGrant(ctx, req)
	case "updateGroupAccess":
		return s.applyUpdateGroupAccess(ctx, req)
	default:
		return fmt.Errorf("unknown change type: %s", req.ChangeType)
	}
}

// Structs matching the exact JSON structure of the intercepted requests.
// We must extract only what we need for execution.

type CreateContractGrantPayload struct {
	ContractAddress string              `json:"contract_address"`
	GroupID         string              `json:"group_id"`
	Functions       []rbac.FunctionRule `json:"functions"`
}

func (s *Server) applyCreateContractGrant(ctx context.Context, req *rbac.ApprovalRequest) error {
	var payload CreateContractGrantPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	contract, err := s.db.GetContractByAddress(ctx, req.OrgID, payload.ContractAddress)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if contract == nil {
		return fmt.Errorf("contract %s not found in org %s", payload.ContractAddress, req.OrgID)
	}

	group, err := s.db.GetGroup(ctx, payload.GroupID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if group == nil || group.OrgID != req.OrgID {
		return fmt.Errorf("group %s not found in org %s", payload.GroupID, req.OrgID)
	}

	grant := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    payload.GroupID,
		Functions:  payload.Functions,
	}

	if err := s.db.CreateContractGrant(ctx, grant); err != nil {
		return fmt.Errorf("failed to create grant: %w", err)
	}

	s.rbacAccessCtrl.InvalidateGroup(ctx, payload.GroupID)
	return nil
}

type UpdateContractGrantPayload struct {
	ContractAddress string              `json:"contract_address"`
	GroupID         string              `json:"group_id"`
	Functions       []rbac.FunctionRule `json:"functions"` // nil means all functions
	IsNullFunctions bool                `json:"is_null_functions"` // if true, clear specific rules
}

func (s *Server) applyUpdateContractGrant(ctx context.Context, req *rbac.ApprovalRequest) error {
	var payload UpdateContractGrantPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	contract, err := s.db.GetContractByAddress(ctx, req.OrgID, payload.ContractAddress)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if contract == nil {
		return fmt.Errorf("contract %s not found", payload.ContractAddress)
	}

	grant, err := s.db.GetContractGrantByContractAndGroup(ctx, contract.ID, payload.GroupID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if grant == nil {
		return fmt.Errorf("grant not found")
	}

	if payload.IsNullFunctions {
		grant.Functions = nil
	} else if payload.Functions != nil {
		grant.Functions = payload.Functions
	}

	if err := s.db.UpdateContractGrant(ctx, grant); err != nil {
		return fmt.Errorf("failed to update grant: %w", err)
	}

	s.rbacAccessCtrl.InvalidateGroup(ctx, payload.GroupID)
	return nil
}

type DeleteContractGrantPayload struct {
	ContractAddress string `json:"contract_address"`
	GroupID         string `json:"group_id"`
}

func (s *Server) applyDeleteContractGrant(ctx context.Context, req *rbac.ApprovalRequest) error {
	var payload DeleteContractGrantPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	contract, err := s.db.GetContractByAddress(ctx, req.OrgID, payload.ContractAddress)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if contract == nil {
		return fmt.Errorf("contract %s not found", payload.ContractAddress)
	}

	grant, err := s.db.GetContractGrantByContractAndGroup(ctx, contract.ID, payload.GroupID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if grant == nil {
		return fmt.Errorf("grant not found")
	}

	s.rbacAccessCtrl.InvalidateGroup(ctx, payload.GroupID)

	if err := s.db.DeleteContractGrant(ctx, grant.ID); err != nil {
		return fmt.Errorf("failed to delete grant: %w", err)
	}

	return nil
}

type UpdateGroupAccessPayload struct {
	GroupID        string   `json:"group_id"`
	AllowedMethods []string `json:"allowed_methods"`
	Claims         []string `json:"claims"` // stored as strings, parsed back to Claims
}

func (s *Server) applyUpdateGroupAccess(ctx context.Context, req *rbac.ApprovalRequest) error {
	var payload UpdateGroupAccessPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	group, err := s.db.GetGroup(ctx, payload.GroupID)
	if err != nil || group == nil || group.OrgID != req.OrgID {
		return fmt.Errorf("group not found or invalid org")
	}

	access, err := s.db.GetGroupAccess(ctx, payload.GroupID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	if access == nil {
		return fmt.Errorf("group access not found")
	}

	var claims []rbac.Claim
	for _, c := range payload.Claims {
		claims = append(claims, rbac.Claim(c))
	}
	// Always expand claims
	access.Claims = rbac.ExpandClaims(claims)
	
	if payload.AllowedMethods != nil {
		access.AllowedMethods = payload.AllowedMethods
	}

	if err := s.db.UpdateGroupAccess(ctx, access); err != nil {
		return fmt.Errorf("failed to update group access: %w", err)
	}

	s.rbacAccessCtrl.InvalidateGroup(ctx, payload.GroupID)
	return nil
}
