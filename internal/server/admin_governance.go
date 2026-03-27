package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// List Governance Requests
// GET /orgs/:org_id/governance/requests
func (s *Server) listGovernanceRequests(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := parsePaginationParams(c, 50)

	filter := db.ApprovalRequestFilter{}
	if status := c.Query("status"); status != "" {
		st := rbac.ApprovalRequestStatus(status)
		filter.Status = &st
	}
	if reqID := c.Query("requester_id"); reqID != "" {
		filter.RequesterID = &reqID
	}
	if cType := c.Query("change_type"); cType != "" {
		filter.ChangeType = &cType
	}

	reqs, total, err := s.db.ListApprovalRequests(c.Request.Context(), orgID, limit, offset, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": reqs, "total": total, "limit": limit, "offset": offset})
}

// Get Governance Request details including decisions
// GET /orgs/:org_id/governance/requests/:request_id
func (s *Server) getGovernanceRequest(c *gin.Context) {
	orgID := c.Param("org_id")
	requestID := c.Param("request_id")

	req, err := s.db.GetApprovalRequest(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req == nil || req.OrgID != orgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}

	decisions, err := s.db.GetApprovalDecisions(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request":   req,
		"decisions": decisions,
	})
}

// Approve Governance Request
// POST /orgs/:org_id/governance/requests/:request_id/approve
func (s *Server) approveGovernanceRequest(c *gin.Context) {
	orgID := c.Param("org_id")
	requestID := c.Param("request_id")

	var input struct {
		Reason string `json:"reason"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	approverID := c.GetString("admin_user_id")
	if approverID == "" {
		approverID = "00000000-0000-0000-0000-000000000000"
	}

	if s.governanceEngine == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "governance engine not initialized"})
		return
	}

	var reasonPtr *string
	if input.Reason != "" {
		reasonPtr = &input.Reason
	}

	// This validates orgID matching inside the engine and processes the decision
	req, err := s.governanceEngine.ProcessDecision(c.Request.Context(), orgID, requestID, approverID, "approve", reasonPtr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		// E2E DEBUG HOOK: Print the exact trace triggering HTTP 400
		println("[CRITICAL E2E DEBUG] ProcessDecision failed: " + err.Error())
		return
	}

	if req.OrgID != orgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found in this organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "decision recorded", "request": req})
}

// Reject Governance Request
// POST /orgs/:org_id/governance/requests/:request_id/reject
func (s *Server) rejectGovernanceRequest(c *gin.Context) {
	orgID := c.Param("org_id")
	requestID := c.Param("request_id")

	var input struct {
		Reason string `json:"reason" binding:"required"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required to reject"})
		return
	}

	approverID := c.GetString("admin_user_id")
	if approverID == "" {
		approverID = "00000000-0000-0000-0000-000000000000"
	}

	if s.governanceEngine == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "governance engine not initialized"})
		return
	}

	req, err := s.governanceEngine.ProcessDecision(c.Request.Context(), orgID, requestID, approverID, "reject", &input.Reason)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.OrgID != orgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found in this organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "decision recorded", "request": req})
}

// Get Governance Settings
// GET /orgs/:org_id/governance/settings
func (s *Server) getGovernanceSettings(c *gin.Context) {
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

	approverGroups, err := s.db.ListGovernanceApproverGroups(c.Request.Context(), orgID)
	if err != nil {
		approverGroups = nil
	}

	c.JSON(http.StatusOK, gin.H{
		"governance_enabled":                  org.GovernanceEnabled,
		"approval_threshold":                  org.ApprovalThreshold,
		"governance_webhook_url":              org.GovernanceWebhookURL,
		"governance_escalation_timeout_hours": org.GovernanceEscalationTimeoutHours,
		"approver_groups":                     approverGroups,
	})
}

// Update Governance Settings
// PUT /orgs/:org_id/governance/settings
func (s *Server) updateGovernanceSettings(c *gin.Context) {
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
		GovernanceEnabled                *bool   `json:"governance_enabled"`
		ApprovalThreshold                *int    `json:"approval_threshold"`
		GovernanceWebhookURL             *string `json:"governance_webhook_url"`
		GovernanceEscalationTimeoutHours *int    `json:"governance_escalation_timeout_hours"`
	}

	// We MUST allow nulls for GovernanceWebhookURL, so we unmarshal manually or use specific bindings.
	// But simple unmarshal works if the user doesn't send the key or sends null.
	bodyBytes, _ := c.GetRawData()
	if err := json.Unmarshal(bodyBytes, &input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload: " + err.Error()})
		return
	}

	// Track explicitly sent nulls to unset GovernanceWebhookURL
	var rawMap map[string]json.RawMessage
	_ = json.Unmarshal(bodyBytes, &rawMap)
	
	unsetWebhook := false
	if val, exists := rawMap["governance_webhook_url"]; exists && string(val) == "null" {
		unsetWebhook = true
	}

	if input.GovernanceEnabled != nil {
		org.GovernanceEnabled = *input.GovernanceEnabled
	}
	if input.ApprovalThreshold != nil {
		if *input.ApprovalThreshold < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "approval_threshold must be at least 1"})
			return
		}
		org.ApprovalThreshold = *input.ApprovalThreshold
	}
	
	if unsetWebhook {
		org.GovernanceWebhookURL = nil
	} else if input.GovernanceWebhookURL != nil {
		org.GovernanceWebhookURL = input.GovernanceWebhookURL
	}
	
	if input.GovernanceEscalationTimeoutHours != nil {
		org.GovernanceEscalationTimeoutHours = *input.GovernanceEscalationTimeoutHours
	}

	// Validate threshold when enabling
	if org.GovernanceEnabled && org.ApprovalThreshold < 1 {
		org.ApprovalThreshold = 1 // default to 1 if enabling without setting
	}

	if err := s.db.UpdateOrganization(c.Request.Context(), org); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update settings: " + err.Error()})
		return
	}

	// Include approver groups in the response for convenience
	approverGroups, err := s.db.ListGovernanceApproverGroups(c.Request.Context(), orgID)
	if err != nil {
		// Non-fatal: return settings without approver groups
		approverGroups = nil
	}

	c.JSON(http.StatusOK, gin.H{
		"governance_enabled":                  org.GovernanceEnabled,
		"approval_threshold":                  org.ApprovalThreshold,
		"governance_webhook_url":              org.GovernanceWebhookURL,
		"governance_escalation_timeout_hours": org.GovernanceEscalationTimeoutHours,
		"approver_groups":                     approverGroups,
	})
}
