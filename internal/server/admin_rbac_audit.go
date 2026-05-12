package server

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// Audit Log handlers

// listAuditLogs returns RBAC audit log rows.
//
// Audit H1: pre-fix this endpoint returned every audit entry across
// every org for a given resource_type / actor_id query. A tier-2
// admin of Org A could enumerate is_org_admin mutations, group
// renames, contract changes, and actor identities across the entire
// cluster.
//
// Fix: super-admin sees everything; JWT admins receive only entries
// whose resource lives in one of their admin_org_ids /
// admin_readonly_org_ids. The DB layer filters at the SQL level so
// the response cardinality cannot be used as an enumeration oracle.
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

	// Compute caller's scope. nil means super-admin / dev (no filter).
	scopedOrgIDs := callerOrgScope(c)

	// Use actor filter if provided
	if actorID != "" {
		logs, err := s.db.ListAuditLogsByActorScoped(ctx, actorID, scopedOrgIDs, limit, offset)
		if err != nil {
			respondInternalError(c, err.Error())
			return
		}
		respondOK(c, logs)
		return
	}

	// Use resource type filter
	logs, err := s.db.ListAuditLogsScoped(ctx, resourceType, resourceIDPtr, scopedOrgIDs, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	respondOK(c, logs)
}

// callerOrgScope returns the org IDs the JWT-admin caller may see
// (union of full-admin and read-only-admin org IDs), or nil for
// super-admin / dev-mode callers (= no filter).
func callerOrgScope(c *gin.Context) []string {
	if c.GetString("auth_method") != "jwt_admin" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				if _, dup := seen[id]; !dup {
					seen[id] = struct{}{}
					out = append(out, id)
				}
			}
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				if _, dup := seen[id]; !dup {
					seen[id] = struct{}{}
					out = append(out, id)
				}
			}
		}
	}
	// Empty slice (not nil) signals "caller is jwt_admin with no
	// orgs" — the SQL layer should return zero rows in that case.
	return out
}
