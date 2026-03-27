package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// governanceMiddleware intercepts mutating admin requests if governance is enabled.
func (s *Server) governanceMiddleware(changeType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("org_id")
		if orgID == "" {
			c.Next()
			return
		}

		org, err := s.db.GetOrganization(c.Request.Context(), orgID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "database error"})
			return
		}
		if org == nil || !org.GovernanceEnabled {
			// Governance not enabled or org not found, proceed normally
			c.Next()
			return
		}

		// Check if we have an initialized governance engine
		if s.governanceEngine == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "governance engine not initialized"})
			return
		}

		// Get requester identity
		requesterID := c.GetString("admin_user_id")
		if requesterID == "" {
			requesterID = "00000000-0000-0000-0000-000000000000" // fallback for API tokens (System User UUID)
		}

		// Read the original request body
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, err = io.ReadAll(c.Request.Body)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
				return
			}
			// Restore the body for further use if needed
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Construct payload based on changeType
		var payload []byte
		var targetTypeStr string
		var targetType *string
		switch changeType {
		case "createContractGrant":
			targetTypeStr = "ContractGrant"
			targetType = &targetTypeStr
			address := c.Param("address")
			var p CreateContractGrantPayload
			if len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &p); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid payload: " + err.Error()})
					return
				}
			}
			p.ContractAddress = address
			payload, _ = json.Marshal(p)

		case "updateContractGrant":
			targetTypeStr = "ContractGrant"
			targetType = &targetTypeStr
			address := c.Param("address")
			groupID := c.Param("group_id")
			var p UpdateContractGrantPayload
			if len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &p); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid payload: " + err.Error()})
					return
				}
			}
			p.ContractAddress = address
			p.GroupID = groupID
			
			// Detect if Functions was explicitly null
			if len(bodyBytes) > 0 {
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(bodyBytes, &rawMap)
				if val, exists := rawMap["functions"]; exists && string(val) == "null" {
					p.IsNullFunctions = true
				}
			}
			payload, _ = json.Marshal(p)

		case "deleteContractGrant":
			targetTypeStr = "ContractGrant"
			targetType = &targetTypeStr
			address := c.Param("address")
			groupID := c.Param("group_id")
			p := DeleteContractGrantPayload{
				ContractAddress: address,
				GroupID:         groupID,
			}
			payload, _ = json.Marshal(p)

		case "updateGroupAccess":
			targetTypeStr = "GroupAccess"
			targetType = &targetTypeStr
			groupID := c.Param("group_id")
			var p UpdateGroupAccessPayload
			if len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &p); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid payload: " + err.Error()})
					return
				}
			}
			p.GroupID = groupID
			payload, _ = json.Marshal(p)

		default:
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "unsupported governance change type"})
			return
		}

		req, err := s.governanceEngine.SubmitChange(
			c.Request.Context(), 
			orgID, 
			requesterID, 
			changeType, 
			nil, // targetID is nil
			targetType, 
			payload, 
			org.ApprovalThreshold,
		)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to submit approval request: " + err.Error()})
			return
		}

		// Return 202 Accepted
		c.AbortWithStatusJSON(http.StatusAccepted, gin.H{
			"message": "Change requires governance approval",
			"request_id": req.ID,
			"status": req.Status,
		})
	}
}
