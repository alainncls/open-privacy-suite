package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/rbac"
)

// List Governance Approver Groups
// GET /orgs/:org_id/governance/approvers
func (s *Server) listGovernanceApproverGroups(c *gin.Context) {
	orgID := c.Param("org_id")

	groups, err := s.db.ListGovernanceApproverGroups(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list approver groups"})
		return
	}

	if groups == nil {
		groups = make([]*rbac.GovernanceApproverGroup, 0)
	}

	c.JSON(http.StatusOK, gin.H{"data": groups})
}

// Add Governance Approver Group
// POST /orgs/:org_id/governance/approvers
func (s *Server) addGovernanceApproverGroup(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		GroupID string `json:"group_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_id is required"})
		return
	}

	// Verify the group exists and belongs to this org
	group, err := s.db.GetGroup(c.Request.Context(), input.GroupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	if group == nil || group.OrgID != orgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found in this organization"})
		return
	}

	if err := s.db.AddGovernanceApproverGroup(c.Request.Context(), orgID, input.GroupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add approver group"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "approver group added", "group_id": input.GroupID})
}

// Remove Governance Approver Group
// DELETE /orgs/:org_id/governance/approvers/:group_id
func (s *Server) removeGovernanceApproverGroup(c *gin.Context) {
	orgID := c.Param("org_id")
	groupID := c.Param("group_id")

	if err := s.db.RemoveGovernanceApproverGroup(c.Request.Context(), orgID, groupID); err != nil {
        if err.Error() == "not found" || err.Error() == "sql: no rows in result set" {
		    c.JSON(http.StatusNotFound, gin.H{"error": "approver group not found in this organization"})
        } else {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
        }
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "approver group removed"})
}
