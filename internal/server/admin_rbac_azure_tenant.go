package server

import (
	"log/slog"
	"strings"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Azure Tenant admin handlers
//
// Audit C4: every endpoint here is a cluster-wide primitive — a
// tier-2 admin in Org A creating an Azure tenant entry with
// default_org_id=B + auto_provision=true escalates themselves to
// admin of Org B via Azure SSO. Deleting a tenant entry triggers
// BanUsersByTenantID which mass-bans every user authenticated
// through that Azure tenant regardless of org. Restrict to
// super-admin (X-Admin-Token) for every mutation; reads also
// restricted because the entries reveal the cluster's SSO topology.

func (s *Server) listAzureTenants(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	tenants, err := s.db.ListAllowedAzureTenants(c.Request.Context())
	if err != nil {
		slog.Error("failed to list Azure tenants", "error", err)
		respondInternalError(c, "internal server error")
		return
	}
	respondOK(c, gin.H{"data": tenants})
}

func (s *Server) createAzureTenant(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	var input struct {
		TenantID       string  `json:"tenant_id" binding:"required"`
		Label          string  `json:"label"`
		DefaultOrgID   *string `json:"default_org_id"`
		DefaultGroupID *string `json:"default_group_id"`
		AutoProvision  *bool   `json:"auto_provision"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_azure_tenant: invalid create body", "err", err)
		return
	}

	// MEDIUM-3: Validate tenant_id is a valid UUID
	if _, err := uuid.Parse(input.TenantID); err != nil {
		respondBadRequest(c, "tenant_id must be a valid UUID")
		return
	}

	// MEDIUM-1: Cross-validate default_org_id and default_group_id
	if input.DefaultOrgID != nil && input.DefaultGroupID != nil {
		group, err := s.db.GetGroup(c.Request.Context(), *input.DefaultGroupID)
		if err != nil {
			slog.Error("failed to look up group", "group_id", *input.DefaultGroupID, "error", err)
			respondInternalError(c, "internal server error")
			return
		}
		if group == nil {
			respondBadRequest(c, "default_group_id does not exist")
			return
		}
		if group.OrgID != *input.DefaultOrgID {
			respondBadRequest(c, "default_group_id does not belong to default_org_id")
			return
		}
		// RD-1107: SSO auto-provisioning must not land users in an admin-tier
		// group — that would auto-mint org admins without explicit onboarding.
		if group.IsOrgAdmin || group.IsOrgReadonlyAdmin {
			respondBadRequest(c, "default_group_id must not be an org-admin or readonly-admin group")
			return
		}
	}

	autoProvision := true
	if input.AutoProvision != nil {
		autoProvision = *input.AutoProvision
	}

	tenant := &db.AllowedAzureTenant{
		ID:             uuid.New().String(),
		TenantID:       input.TenantID,
		Label:          input.Label,
		DefaultOrgID:   input.DefaultOrgID,
		DefaultGroupID: input.DefaultGroupID,
		AutoProvision:  autoProvision,
	}

	result, err := s.db.CreateAllowedAzureTenant(c.Request.Context(), tenant)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "tenant with this tenant_id already exists")
			return
		}
		slog.Error("failed to create Azure tenant", "error", err)
		respondInternalError(c, "internal server error")
		return
	}

	s.recordAuditAction(c, rbac.AuditActionCreate, rbac.ResourceTypeAzureTenant, result.ID, result.TenantID,
		nil,
		map[string]any{
			"tenant_id":        result.TenantID,
			"label":            result.Label,
			"default_org_id":   result.DefaultOrgID,
			"default_group_id": result.DefaultGroupID,
			"auto_provision":   result.AutoProvision,
		})

	respondCreated(c, result)
}

func (s *Server) getAzureTenant(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	id := c.Param("id")
	tenant, err := s.db.GetAllowedAzureTenant(c.Request.Context(), id)
	if err != nil {
		slog.Error("failed to get Azure tenant", "id", id, "error", err)
		respondInternalError(c, "internal server error")
		return
	}
	if tenant == nil {
		respondNotFound(c, "azure tenant not found")
		return
	}
	respondOK(c, tenant)
}

func (s *Server) updateAzureTenant(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	id := c.Param("id")

	tenant, err := s.db.GetAllowedAzureTenant(c.Request.Context(), id)
	if err != nil {
		slog.Error("failed to get Azure tenant for update", "id", id, "error", err)
		respondInternalError(c, "internal server error")
		return
	}
	if tenant == nil {
		respondNotFound(c, "azure tenant not found")
		return
	}

	var input struct {
		TenantID       *string `json:"tenant_id"`
		Label          *string `json:"label"`
		DefaultOrgID   *string `json:"default_org_id"`
		DefaultGroupID *string `json:"default_group_id"`
		AutoProvision  *bool   `json:"auto_provision"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_azure_tenant: invalid update body", "err", err)
		return
	}

	// MEDIUM-3: Validate tenant_id is a valid UUID if being updated
	if input.TenantID != nil {
		if _, err := uuid.Parse(*input.TenantID); err != nil {
			respondBadRequest(c, "tenant_id must be a valid UUID")
			return
		}
		tenant.TenantID = *input.TenantID
	}
	if input.Label != nil {
		tenant.Label = *input.Label
	}
	if input.DefaultOrgID != nil {
		if *input.DefaultOrgID == "" {
			tenant.DefaultOrgID = nil
		} else {
			tenant.DefaultOrgID = input.DefaultOrgID
		}
	}
	if input.DefaultGroupID != nil {
		if *input.DefaultGroupID == "" {
			tenant.DefaultGroupID = nil
		} else {
			tenant.DefaultGroupID = input.DefaultGroupID
		}
	}
	if input.AutoProvision != nil {
		tenant.AutoProvision = *input.AutoProvision
	}

	// MEDIUM-1: Cross-validate default_org_id and default_group_id
	if tenant.DefaultOrgID != nil && tenant.DefaultGroupID != nil {
		group, err := s.db.GetGroup(c.Request.Context(), *tenant.DefaultGroupID)
		if err != nil {
			slog.Error("failed to look up group", "group_id", *tenant.DefaultGroupID, "error", err)
			respondInternalError(c, "internal server error")
			return
		}
		if group == nil {
			respondBadRequest(c, "default_group_id does not exist")
			return
		}
		if group.OrgID != *tenant.DefaultOrgID {
			respondBadRequest(c, "default_group_id does not belong to default_org_id")
			return
		}
		// RD-1107: SSO auto-provisioning must not land users in an admin-tier
		// group — that would auto-mint org admins without explicit onboarding.
		if group.IsOrgAdmin || group.IsOrgReadonlyAdmin {
			respondBadRequest(c, "default_group_id must not be an org-admin or readonly-admin group")
			return
		}
	}

	before := map[string]any{
		"tenant_id":        tenant.TenantID,
		"label":            tenant.Label,
		"default_org_id":   tenant.DefaultOrgID,
		"default_group_id": tenant.DefaultGroupID,
		"auto_provision":   tenant.AutoProvision,
	}

	result, err := s.db.UpdateAllowedAzureTenant(c.Request.Context(), tenant)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "tenant with this tenant_id already exists")
			return
		}
		slog.Error("failed to update Azure tenant", "id", id, "error", err)
		respondInternalError(c, "internal server error")
		return
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeAzureTenant, result.ID, result.TenantID,
		before,
		map[string]any{
			"tenant_id":        result.TenantID,
			"label":            result.Label,
			"default_org_id":   result.DefaultOrgID,
			"default_group_id": result.DefaultGroupID,
			"auto_provision":   result.AutoProvision,
		})

	respondOK(c, result)
}

func (s *Server) deleteAzureTenant(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	id := c.Param("id")

	// Look up the tenant to get its Azure tenant_id before deleting
	tenant, err := s.db.GetAllowedAzureTenant(c.Request.Context(), id)
	if err != nil {
		slog.Error("failed to look up Azure tenant", "id", id, "error", err)
		respondInternalError(c, "internal server error")
		return
	}
	if tenant == nil {
		respondNotFound(c, "azure tenant not found")
		return
	}

	if err := s.db.DeleteAllowedAzureTenant(c.Request.Context(), id); err != nil {
		if err == db.ErrNotFound {
			respondNotFound(c, "azure tenant not found")
			return
		}
		slog.Error("failed to delete Azure tenant", "id", id, "error", err)
		respondInternalError(c, "internal server error")
		return
	}

	// Ban all users from this tenant and revoke their sessions
	banned, banErr := s.db.BanUsersByTenantID(c.Request.Context(), tenant.TenantID, "Azure AD tenant removed")
	if banErr != nil {
		slog.Warn("failed to ban users for tenant", "tenant_id", tenant.TenantID, "error", banErr)
	} else if banned > 0 {
		slog.Info("banned users from deleted Azure tenant", "count", banned, "tenant_id", tenant.TenantID)
	}

	revoked, revokeErr := s.db.RevokeRefreshTokensByTenantID(c.Request.Context(), tenant.TenantID)
	if revokeErr != nil {
		slog.Warn("failed to revoke refresh tokens for tenant", "tenant_id", tenant.TenantID, "error", revokeErr)
	} else if revoked > 0 {
		slog.Info("revoked refresh tokens for deleted Azure tenant", "count", revoked, "tenant_id", tenant.TenantID)
	}

	s.recordAuditAction(c, rbac.AuditActionDelete, rbac.ResourceTypeAzureTenant, tenant.ID, tenant.TenantID,
		map[string]any{
			"tenant_id":        tenant.TenantID,
			"label":            tenant.Label,
			"default_org_id":   tenant.DefaultOrgID,
			"default_group_id": tenant.DefaultGroupID,
			"auto_provision":   tenant.AutoProvision,
			"users_banned":     banned,
			"tokens_revoked":   revoked,
		},
		nil)

	respondDeleted(c, "azure tenant")
}
