package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/rbac"
)

// registerDisclosureRoutes registers admin disclosure API endpoints.
//
// SECURITY: These endpoints are protected by localhostOnlyMiddleware (applied in server.go).
// This means only requests from localhost, Docker networks, or Tailscale are allowed.
// The admin UI runs on localhost and is the intended consumer of these APIs.
//
// Authorization model: These are super-admin endpoints that can access all organizations.
// This is intentional for a central admin interface managing multiple orgs.
func (s *Server) registerDisclosureRoutes(api *gin.RouterGroup) {
	disclosureGroup := api.Group("/disclosure")
	{
		// Admin endpoints (for creating requests on behalf of regulators)
		// SECURITY: Protected by localhostOnlyMiddleware - admin-only access
		disclosureGroup.POST("/requests", s.createDisclosureRequest)
		disclosureGroup.GET("/requests", s.listDisclosureRequests)
		disclosureGroup.GET("/requests/:request_id", s.getDisclosureRequest)
		disclosureGroup.DELETE("/requests/:request_id", s.deleteDisclosureRequest)

		// Admin grant management
		// SECURITY: Protected by localhostOnlyMiddleware - admin-only access
		disclosureGroup.GET("/grants", s.listDisclosureGrants)
		disclosureGroup.POST("/grants/:grant_id/revoke", s.adminRevokeDisclosureGrant)

		// Block explorer integration - check if a DID has access to a user's data
		disclosureGroup.GET("/check-access", s.checkDisclosureAccess)

		// Grant access endpoints (require disclosure token)
		disclosureGroup.GET("/grants/:grant_id/logs", s.getDisclosureLogs)
		disclosureGroup.GET("/grants/:grant_id/summary", s.getDisclosureSummary)
		disclosureGroup.GET("/grants/:grant_id/report/:report_type", s.getDisclosureReport)
		disclosureGroup.GET("/grants/:grant_id/events", s.getDisclosureEvents)
	}
}

// registerUserDisclosureRoutes registers user-facing disclosure endpoints (public with JWT auth).
func (s *Server) registerUserDisclosureRoutes(router *gin.Engine) {
	// User-facing endpoints (require JWT auth, accessible from external IPs)
	meDisclosure := router.Group("/api/v1/me/disclosure")
	meDisclosure.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	meDisclosure.Use(s.disclosureUserMiddleware())
	{
		meDisclosure.GET("/requests", s.getMyDisclosureRequests)
		meDisclosure.GET("/requests/all", s.getAllMyDisclosureRequests)
		meDisclosure.POST("/requests/:request_id/approve", s.approveDisclosureRequest)
		meDisclosure.POST("/requests/:request_id/reject", s.rejectDisclosureRequest)
		meDisclosure.POST("/requests/:request_id/revoke", s.revokeDisclosureRequest)
		meDisclosure.GET("/grants", s.getMyActiveGrants)
		meDisclosure.GET("/grants/all", s.getAllMyGrants)
	}
}

// disclosureUserMiddleware adds user_id to context from subject (DID)
func (s *Server) disclosureUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, exists := c.Get("subject")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing subject in context"})
			c.Abort()
			return
		}

		// Get user from database
		user, err := s.db.GetUserByExternalID(c.Request.Context(), subject.(string))
		if err != nil || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			c.Abort()
			return
		}

		c.Set("user_id", user.ID)
		c.Next()
	}
}

// createDisclosureRequest creates a new disclosure request (admin endpoint).
//
// Audit C3: pre-fix this endpoint trusted org_id and target_user_id
// from the request body without any caller-scope check. A tier-2
// admin of Org A could manufacture a disclosure request for any Org B
// user; once the target approved, the requester saw that user's ETH
// activity globally via getDisclosedAddressesForViewer. Now the
// handler enforces both org_id ∈ caller_scope and target_user_id ∈
// caller_scope.
func (s *Server) createDisclosureRequest(c *gin.Context) {
	var input struct {
		RequesterUserID string           `json:"requester_user_id"` // Optional - who's requesting (internal user ID)
		RequesterDID    string           `json:"requester_did"`     // DID of authorized viewer (for block explorer auth)
		TargetUserID    string           `json:"target_user_id" binding:"required"`
		OrgID           string           `json:"org_id"` // Defaults to default org
		Scope           disclosure.Scope `json:"scope"`
		Reason          string           `json:"reason" binding:"required"`
		LegalBasis      string           `json:"legal_basis"`
		ExpiresInHours  int              `json:"expires_in_hours"` // 0 = no expiration
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	orgID := input.OrgID
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001" // Default org
	}

	// Cross-org gate. Super-admin / dev: any org. JWT admin: org must
	// be in admin_org_ids (mutating action — read-only not enough).
	if !requireFullAdminInScope(c, orgID) {
		return
	}

	// Target user must share at least one org with the caller. Pre-fix,
	// a tier-2 admin of Org A could manufacture a disclosure request
	// for any Org B user.
	if !s.requireUserInCallerScope(c, input.TargetUserID) {
		return
	}

	var expiresIn *time.Duration
	if input.ExpiresInHours > 0 {
		d := time.Duration(input.ExpiresInHours) * time.Hour
		expiresIn = &d
	}

	req, err := s.disclosureService.CreateRequest(
		c.Request.Context(),
		input.RequesterUserID,
		input.RequesterDID,
		input.TargetUserID,
		orgID,
		input.Scope,
		input.Reason,
		input.LegalBasis,
		expiresIn,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create disclosure request"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionCreate, rbac.ResourceTypeDisclosureRequest, req.ID, input.Reason, orgID,
		nil,
		map[string]any{
			"target_user_id": input.TargetUserID,
			"requester_did":  input.RequesterDID,
			"scope":          input.Scope,
		})

	c.JSON(http.StatusCreated, req)
}

// listDisclosureRequests lists disclosure requests with filtering support.
//
// Audit C3: pre-fix the ?org_id= query was honoured without scope
// check, leaking any org's request list to any tier-2 admin. Now
// clamped to caller's org_id set.
func (s *Server) listDisclosureRequests(c *gin.Context) {
	filter := &disclosure.DisclosureFilter{}

	// Parse org_id
	if orgID := c.Query("org_id"); orgID != "" {
		filter.OrgID = orgID
	} else {
		filter.OrgID = "00000000-0000-0000-0000-000000000001" // Default org
	}

	// Cross-org gate: the requested org must be in caller's scope.
	if !requireTargetInScope(c, filter.OrgID) {
		return
	}

	// Parse status
	if statusStr := c.Query("status"); statusStr != "" {
		st := disclosure.RequestStatus(statusStr)
		filter.Status = &st
	}

	// Parse target_user_id
	if targetUserID := c.Query("target_user_id"); targetUserID != "" {
		filter.TargetUserID = targetUserID
	}

	// Parse requester_did
	if requesterDID := c.Query("requester_did"); requesterDID != "" {
		filter.RequesterDID = requesterDID
	}

	// Parse disclosure_level
	if levelStr := c.Query("disclosure_level"); levelStr != "" {
		level := disclosure.DisclosureLevel(levelStr)
		filter.DisclosureLevel = &level
	}

	// Parse date_from
	if dateFromStr := c.Query("date_from"); dateFromStr != "" {
		dateFrom, err := time.Parse(time.RFC3339, dateFromStr)
		if err == nil {
			filter.DateFrom = &dateFrom
		}
	}

	// Parse date_to
	if dateToStr := c.Query("date_to"); dateToStr != "" {
		dateTo, err := time.Parse(time.RFC3339, dateToStr)
		if err == nil {
			filter.DateTo = &dateTo
		}
	}

	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}

	// Parse offset
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	result, err := s.disclosureService.ListRequestsWithFilter(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// listDisclosureGrants lists disclosure grants with filtering support (admin endpoint).
// Audit C3 — same fix as listDisclosureRequests.
func (s *Server) listDisclosureGrants(c *gin.Context) {
	filter := &disclosure.DisclosureFilter{}

	// Parse org_id. Pre-fix the empty case left filter.OrgID = "" which
	// silently meant "any org" at the DB layer. Now JWT admins MUST
	// supply an org_id (or get clamped to their scope by the cross-org
	// gate below).
	if orgID := c.Query("org_id"); orgID != "" {
		filter.OrgID = orgID
	} else if c.GetString("auth_method") == "jwt_admin" {
		// Default to the first full-admin org. If the caller has none
		// (RO-only) and supplies no org_id, deny.
		if ids, ok := c.Get("admin_org_ids"); ok {
			if list, ok := ids.([]string); ok && len(list) > 0 {
				filter.OrgID = list[0]
			}
		}
		if filter.OrgID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "org_id query parameter is required"})
			return
		}
	}

	// Cross-org gate (only enforced when filter.OrgID is set).
	if filter.OrgID != "" && !requireTargetInScope(c, filter.OrgID) {
		return
	}

	// Parse status (for grants: approved = active, revoked, expired)
	if statusStr := c.Query("status"); statusStr != "" {
		st := disclosure.RequestStatus(statusStr)
		filter.Status = &st
	}

	// Parse target_user_id
	if targetUserID := c.Query("target_user_id"); targetUserID != "" {
		filter.TargetUserID = targetUserID
	}

	// Parse requester_did
	if requesterDID := c.Query("requester_did"); requesterDID != "" {
		filter.RequesterDID = requesterDID
	}

	// Parse disclosure_level
	if levelStr := c.Query("disclosure_level"); levelStr != "" {
		level := disclosure.DisclosureLevel(levelStr)
		filter.DisclosureLevel = &level
	}

	// Parse date_from
	if dateFromStr := c.Query("date_from"); dateFromStr != "" {
		dateFrom, err := time.Parse(time.RFC3339, dateFromStr)
		if err == nil {
			filter.DateFrom = &dateFrom
		}
	}

	// Parse date_to
	if dateToStr := c.Query("date_to"); dateToStr != "" {
		dateTo, err := time.Parse(time.RFC3339, dateToStr)
		if err == nil {
			filter.DateTo = &dateTo
		}
	}

	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}

	// Parse offset
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	result, err := s.disclosureService.ListGrantsWithFilter(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// deleteDisclosureRequest deletes a pending disclosure request (admin endpoint).
// Audit C3: re-verify the loaded request's org is in caller's scope.
func (s *Server) deleteDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")

	// Load the request to find its org before any mutation.
	reqDetails, err := s.db.GetDisclosureRequestWithDetails(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load request"})
		return
	}
	if reqDetails == nil || reqDetails.Request == nil {
		// Generic 403 to avoid existence oracle.
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}
	if !requireFullAdminInScope(c, reqDetails.Request.OrgID) {
		return
	}

	err = s.disclosureService.DeletePendingRequest(c.Request.Context(), requestID)
	if err != nil {
		if err == disclosure.ErrRequestNotFound {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
		if err == disclosure.ErrRequestNotPending {
			c.JSON(http.StatusBadRequest, gin.H{"error": "can only delete pending requests"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete request"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionDelete, rbac.ResourceTypeDisclosureRequest, reqDetails.Request.ID, reqDetails.Request.Reason, reqDetails.Request.OrgID,
		map[string]any{"target_user_id": reqDetails.Request.TargetUserID, "requester_did": reqDetails.Request.RequesterDID, "status": reqDetails.Request.Status},
		nil)

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// adminRevokeDisclosureGrant revokes a disclosure grant (admin endpoint).
// Audit C3: verify the loaded grant belongs to an org in caller's scope.
func (s *Server) adminRevokeDisclosureGrant(c *gin.Context) {
	grantID := c.Param("grant_id")

	// Load grant to find owning org via its parent request.
	grantWithReq, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load grant"})
		return
	}
	if grantWithReq == nil || grantWithReq.Request == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}
	if !requireFullAdminInScope(c, grantWithReq.Request.OrgID) {
		return
	}

	var input struct {
		Reason string `json:"reason"`
	}

	// Allow empty body - reason is optional
	_ = c.ShouldBindJSON(&input)

	if err := s.disclosureService.RevokeGrant(c.Request.Context(), grantID, input.Reason); err != nil {
		if err == disclosure.ErrGrantNotFound {
			c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke grant"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionRevoke, rbac.ResourceTypeDisclosureGrant, grantID, input.Reason, grantWithReq.Request.OrgID,
		map[string]any{"request_id": grantWithReq.Request.ID, "requester_did": grantWithReq.Request.RequesterDID},
		nil)

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// getDisclosureRequest gets a disclosure request by ID.
// Audit C3: verify request's org is in caller's scope.
func (s *Server) getDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")

	reqDetails, err := s.db.GetDisclosureRequestWithDetails(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load request"})
		return
	}
	if reqDetails == nil || reqDetails.Request == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}
	if !requireTargetInScope(c, reqDetails.Request.OrgID) {
		return
	}

	c.JSON(http.StatusOK, reqDetails)
}

// checkDisclosureAccess checks if a requester DID has access to a target user's data.
// This is used by the block explorer to verify auditor permissions.
// GET /api/disclosure/check-access?requester_did=did:...&target_user_did=did:...
func (s *Server) checkDisclosureAccess(c *gin.Context) {
	requesterDID := c.Query("requester_did")
	targetUserDID := c.Query("target_user_did")

	if requesterDID == "" || targetUserDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "requester_did and target_user_did are required"})
		return
	}

	// Check if there's an active grant for this requester DID and target user
	grantWithReq, err := s.db.GetActiveGrantByRequesterDID(c.Request.Context(), requesterDID, targetUserDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if grantWithReq == nil {
		c.JSON(http.StatusOK, gin.H{
			"has_access": false,
			"message":    "No active disclosure grant found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"has_access":       true,
		"grant_id":         grantWithReq.Grant.ID,
		"scope":            grantWithReq.Grant.Scope,
		"expires_at":       grantWithReq.Grant.ExpiresAt,
		"disclosure_level": grantWithReq.Grant.Scope.DisclosureLevel,
	})
}

// getMyDisclosureRequests gets pending disclosure requests for the authenticated user
func (s *Server) getMyDisclosureRequests(c *gin.Context) {
	userID, _ := c.Get("user_id")

	requests, err := s.disclosureService.GetMyPendingRequests(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, requests)
}

// getAllMyDisclosureRequests gets all disclosure requests for the authenticated user (not just pending)
func (s *Server) getAllMyDisclosureRequests(c *gin.Context) {
	userID, _ := c.Get("user_id")

	requests, err := s.disclosureService.GetAllMyRequests(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, requests)
}

// approveDisclosureRequest approves a disclosure request
func (s *Server) approveDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	userID, _ := c.Get("user_id")

	var input struct {
		Scope              *disclosure.Scope `json:"scope"` // Optional - narrow the scope
		GrantDurationHours int               `json:"grant_duration_hours"`
		Reason             string            `json:"reason"`
	}

	// Allow empty body - all fields are optional
	_ = c.ShouldBindJSON(&input)

	// Default grant duration: 24 hours
	grantDuration := 24 * time.Hour
	if input.GrantDurationHours > 0 {
		grantDuration = time.Duration(input.GrantDurationHours) * time.Hour
	}

	// Verify user is the target of the request
	req, err := s.db.GetDisclosureRequest(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if req.TargetUserID != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only approve requests targeting your own data"})
		return
	}

	grant, err := s.disclosureService.ApproveRequest(
		c.Request.Context(),
		requestID,
		userID.(string),
		input.Scope,
		grantDuration,
		input.Reason,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"grant":   grant,
		"message": "Access granted. Authorized viewer can access data via their authenticated session.",
	})
}

// rejectDisclosureRequest rejects a disclosure request
func (s *Server) rejectDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	userID, _ := c.Get("user_id")

	var input struct {
		Reason string `json:"reason"`
	}

	// Allow empty body - reason is optional
	_ = c.ShouldBindJSON(&input)

	// Verify user is the target of the request
	req, err := s.db.GetDisclosureRequest(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if req.TargetUserID != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only reject requests targeting your own data"})
		return
	}

	if err := s.disclosureService.RejectRequest(c.Request.Context(), requestID, userID.(string), input.Reason); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "rejected"})
}

// revokeDisclosureRequest revokes a previously approved disclosure request
func (s *Server) revokeDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	userID, _ := c.Get("user_id")

	var input struct {
		Reason string `json:"reason"`
	}

	// Allow empty body - reason is optional
	_ = c.ShouldBindJSON(&input)

	// Verify user is the target of the request
	req, err := s.db.GetDisclosureRequest(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if req.TargetUserID != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only revoke requests targeting your own data"})
		return
	}

	if err := s.disclosureService.RevokeRequest(c.Request.Context(), requestID, userID.(string), input.Reason); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// getMyActiveGrants gets active disclosure grants for the authenticated user's data
func (s *Server) getMyActiveGrants(c *gin.Context) {
	userID, _ := c.Get("user_id")

	grants, err := s.disclosureService.GetMyActiveGrants(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, grants)
}

// getAllMyGrants gets all disclosure grants for the authenticated user's data (not just active)
func (s *Server) getAllMyGrants(c *gin.Context) {
	userID, _ := c.Get("user_id")

	grants, err := s.disclosureService.GetAllMyGrants(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, grants)
}

// disclosureTokenMiddleware validates disclosure token from header or query param
func (s *Server) validateDisclosureToken(c *gin.Context) (*disclosure.GrantWithRequest, error) {
	// Check header first
	token := c.GetHeader("X-Disclosure-Token")
	if token == "" {
		// Fall back to query param
		token = c.Query("token")
	}

	if token == "" {
		return nil, disclosure.ErrInvalidToken
	}

	return s.disclosureService.ValidateGrantToken(c.Request.Context(), token)
}

// getDisclosureLogs gets activity logs via disclosure grant
func (s *Server) getDisclosureLogs(c *gin.Context) {
	grantID := c.Param("grant_id")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if grantWithReq.Grant.ID != grantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "token does not match grant"})
		return
	}

	limit := 100
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	viewerIP := c.ClientIP()
	viewerUserID := ""
	if uid, exists := c.Get("user_id"); exists {
		viewerUserID = uid.(string)
	}

	logs, err := s.disclosureService.GetActivityLogs(c.Request.Context(), grantID, viewerUserID, viewerIP, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// getDisclosureSummary gets activity summary via disclosure grant
func (s *Server) getDisclosureSummary(c *gin.Context) {
	grantID := c.Param("grant_id")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if grantWithReq.Grant.ID != grantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "token does not match grant"})
		return
	}

	viewerIP := c.ClientIP()
	viewerUserID := ""
	if uid, exists := c.Get("user_id"); exists {
		viewerUserID = uid.(string)
	}

	summary, err := s.disclosureService.GetActivitySummary(c.Request.Context(), grantID, viewerUserID, viewerIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// getDisclosureReport gets or generates a compliance report via disclosure grant
func (s *Server) getDisclosureReport(c *gin.Context) {
	grantID := c.Param("grant_id")
	reportTypeStr := c.Param("report_type")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if grantWithReq.Grant.ID != grantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "token does not match grant"})
		return
	}

	reportType := disclosure.ReportType(reportTypeStr)
	switch reportType {
	case disclosure.ReportActivitySummary, disclosure.ReportSanctionsCheck, disclosure.ReportCompliance:
		// Valid report type
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid report type"})
		return
	}

	viewerIP := c.ClientIP()
	viewerUserID := ""
	if uid, exists := c.Get("user_id"); exists {
		viewerUserID = uid.(string)
	}

	report, err := s.disclosureService.GenerateComplianceReport(c.Request.Context(), grantID, viewerUserID, viewerIP, reportType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

// getDisclosureEvents gets disclosure access events for a grant
func (s *Server) getDisclosureEvents(c *gin.Context) {
	grantID := c.Param("grant_id")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if grantWithReq.Grant.ID != grantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "token does not match grant"})
		return
	}

	limit := 100
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	events, err := s.db.ListDisclosureEventsByGrant(c.Request.Context(), grantID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}
