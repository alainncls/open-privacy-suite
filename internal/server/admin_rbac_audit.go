package server

import (
	"log/slog"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Audit Log handlers

func (s *Server) listAuditLogs(c *gin.Context) {
	// Parse pagination params
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

	// Parse filter params
	resourceType := c.Query("resource_type")
	resourceID := c.Query("resource_id")
	actorID := c.Query("actor_id")

	// At least one filter must be provided to avoid massive queries
	if resourceType == "" && actorID == "" {
		respondBadRequest(c, "at least one filter (resource_type or actor_id) is required")
		return
	}

	var resourceIDPtr *string
	if resourceID != "" {
		resourceIDPtr = &resourceID
	}

	ctx := c.Request.Context()

	// Use actor filter if provided
	if actorID != "" {
		logs, err := s.db.ListAuditLogsByActor(ctx, actorID, limit, offset)
		if err != nil {
			slog.Error("failed to list audit logs by actor", "error", err)
			respondInternalError(c, "request failed")
			return
		}
		respondOK(c, logs)
		return
	}

	// Use resource type filter
	logs, err := s.db.ListAuditLogs(ctx, resourceType, resourceIDPtr, limit, offset)
	if err != nil {
		slog.Error("failed to list audit logs", "error", err)
		respondInternalError(c, "request failed")
		return
	}
	respondOK(c, logs)
}
