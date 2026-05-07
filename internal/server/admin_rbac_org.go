package server

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// slugRegex validates that slugs contain only letters (case-insensitive), numbers, hyphens, and underscores.
// Slugs must start with a letter or number, not a hyphen or underscore.
var slugRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// validateSlug checks if a slug is valid for use in URLs and database storage.
// Returns an error message if invalid, empty string if valid.
func validateSlug(slug string) string {
	if slug == "" {
		return "slug is required"
	}
	if len(slug) > 100 {
		return "slug must be 100 characters or less"
	}
	if !slugRegex.MatchString(slug) {
		return "slug must contain only letters, numbers, hyphens, and underscores, and start with a letter or number"
	}
	return ""
}

// parsePaginationParams extracts limit and offset from query parameters with defaults.
func parsePaginationParams(c *gin.Context, defaultLimit int) (limit, offset int) {
	limit = defaultLimit
	offset = 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return
}

// Organization handlers

// listOrganizations enumerates orgs visible to the caller.
//
// Cross-org isolation (RD-916): super-admin (X-Admin-Token) sees every org.
// JWT admins see only orgs where they're is_org_admin or is_org_readonly_admin
// — i.e. their tenant boundary matches what `orgScopingMiddleware` already
// enforces on per-:org_id routes. Without this scope a JWT admin of org A
// could enumerate every other tenant's slug/name/UUID via this endpoint.
func (s *Server) listOrganizations(c *gin.Context) {
	limit, offset := parsePaginationParams(c, 50)

	var (
		orgs  []*rbac.Organization
		total int
		err   error
	)
	if c.GetString("auth_method") == "jwt_admin" {
		// Build the visible-orgs set from middleware-populated context.
		// Both is_org_admin and is_org_readonly_admin grant visibility — a
		// readonly admin still has legitimate dashboard access to their org.
		seen := make(map[string]struct{})
		var allowed []string
		appendUnique := func(ids []string) {
			for _, id := range ids {
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				allowed = append(allowed, id)
			}
		}
		if v, ok := c.Get("admin_org_ids"); ok {
			if slice, ok := v.([]string); ok {
				appendUnique(slice)
			}
		}
		if v, ok := c.Get("admin_readonly_org_ids"); ok {
			if slice, ok := v.([]string); ok {
				appendUnique(slice)
			}
		}
		orgs, total, err = s.db.ListOrganizationsByIDsPaginated(c.Request.Context(), allowed, limit, offset)
	} else {
		// admin_token (super-admin) — full visibility.
		orgs, total, err = s.db.ListOrganizationsPaginated(c.Request.Context(), limit, offset)
	}
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}

	includeSystem := c.Query("include_system") == "true"
	filtered := make([]*rbac.Organization, 0, len(orgs))
	for _, org := range orgs {
		if s.config.HideDevAdminOrg && org.Slug == "dev-admin-org" {
			continue
		}
		// is_system rows (e.g. the anonymous org from RD-870) are hidden by
		// default and only surface when ?include_system=true is passed.
		if org.IsSystem && !includeSystem {
			continue
		}
		filtered = append(filtered, org)
	}
	total -= len(orgs) - len(filtered)
	orgs = filtered
	respondOK(c, gin.H{"data": orgs, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) createOrganization(c *gin.Context) {
	// Tenant lifecycle (creating a new org / tenant) is platform-level and
	// reserved for super-admin (X-Admin-Token). JWT-admin tier-2 cannot
	// create orgs — they're scoped to managing existing tenants. Mirrors the
	// is_org_admin escalation gate in createGroup (admin_rbac_group.go:73).
	// RD-917 §1.
	if c.GetString("auth_method") != "admin_token" {
		respondForbidden(c, "only super admin can create organizations")
		return
	}

	var input struct {
		Slug     string         `json:"slug" binding:"required"`
		Name     string         `json:"name" binding:"required"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, err.Error())
		return
	}

	// Validate slug format before database insertion
	if errMsg := validateSlug(input.Slug); errMsg != "" {
		respondBadRequest(c, errMsg)
		return
	}

	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     input.Slug,
		Name:     input.Name,
		Settings: input.Settings,
	}
	if org.Settings == nil {
		org.Settings = make(map[string]any)
	}

	if err := s.db.CreateOrganization(c.Request.Context(), org); err != nil {
		// Check for unique constraint violation (duplicate slug)
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "organization with this slug already exists")
			return
		}
		respondInternalError(c, err.Error())
		return
	}

	respondCreated(c, org)
}

func (s *Server) getOrganization(c *gin.Context) {
	orgID := c.Param("org_id")
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	respondOK(c, org)
}

func (s *Server) updateOrganization(c *gin.Context) {
	orgID := c.Param("org_id")

	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	if org.IsSystem {
		// is_system rows are identity-immutable. Their group_access can be
		// edited via the dedicated PUT endpoint (super-admin only); the org
		// row itself (slug/name) is locked.
		respondForbidden(c, "system organization cannot be modified")
		return
	}

	var input struct {
		Slug     *string        `json:"slug"`
		Name     *string        `json:"name"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, err.Error())
		return
	}

	if input.Slug != nil {
		// Validate slug format before update
		if errMsg := validateSlug(*input.Slug); errMsg != "" {
			respondBadRequest(c, errMsg)
			return
		}
		org.Slug = *input.Slug
	}
	if input.Name != nil {
		org.Name = *input.Name
	}
	if input.Settings != nil {
		org.Settings = input.Settings
	}

	if err := s.db.UpdateOrganization(c.Request.Context(), org); err != nil {
		// Check for unique constraint violation (duplicate slug)
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "organization with this slug already exists")
			return
		}
		respondInternalError(c, err.Error())
		return
	}

	respondOK(c, org)
}

func (s *Server) deleteOrganization(c *gin.Context) {
	// Tenant deletion is platform-level and reserved for super-admin
	// (X-Admin-Token). Tier-2 admins retain read + edit-metadata on their
	// own orgs, but DELETE is locked: deleting a tenant is operator
	// territory, not in-tenant authority. RD-917 §1.
	if c.GetString("auth_method") != "admin_token" {
		respondForbidden(c, "only super admin can delete organizations")
		return
	}

	orgID := c.Param("org_id")

	// Prevent deleting the default organization
	if orgID == rbac.DefaultOrgID {
		respondBadRequest(c, "cannot delete the default organization")
		return
	}

	// Check if organization exists
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	if org.IsSystem {
		respondForbidden(c, "system organization cannot be deleted")
		return
	}

	// Delete the organization (cascades to groups, contracts, etc. via DB constraints)
	if err := s.db.DeleteOrganization(c.Request.Context(), orgID); err != nil {
		respondInternalError(c, err.Error())
		return
	}

	// Invalidate cache for this organization
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	respondDeleted(c, "organization")
}
