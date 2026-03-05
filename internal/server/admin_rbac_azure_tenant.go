package server

import (
	"log"
	"strings"

	"privacy-proxy/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Azure Tenant admin handlers

func (s *Server) listAzureTenants(c *gin.Context) {
	tenants, err := s.db.ListAllowedAzureTenants(c.Request.Context())
	if err != nil {
		log.Printf("Error listing Azure tenants: %v", err)
		respondInternalError(c, "internal server error")
		return
	}
	respondOK(c, gin.H{"data": tenants})
}

func (s *Server) createAzureTenant(c *gin.Context) {
	var input struct {
		TenantID       string  `json:"tenant_id" binding:"required"`
		Label          string  `json:"label"`
		DefaultOrgID   *string `json:"default_org_id"`
		DefaultGroupID *string `json:"default_group_id"`
		AutoProvision  *bool   `json:"auto_provision"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, err.Error())
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
			log.Printf("Error looking up group %s: %v", *input.DefaultGroupID, err)
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
		log.Printf("Error creating Azure tenant: %v", err)
		respondInternalError(c, "internal server error")
		return
	}

	respondCreated(c, result)
}

func (s *Server) getAzureTenant(c *gin.Context) {
	id := c.Param("id")
	tenant, err := s.db.GetAllowedAzureTenant(c.Request.Context(), id)
	if err != nil {
		log.Printf("Error getting Azure tenant %s: %v", id, err)
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
	id := c.Param("id")

	tenant, err := s.db.GetAllowedAzureTenant(c.Request.Context(), id)
	if err != nil {
		log.Printf("Error getting Azure tenant %s for update: %v", id, err)
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
		respondBadRequest(c, err.Error())
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
			log.Printf("Error looking up group %s: %v", *tenant.DefaultGroupID, err)
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
	}

	result, err := s.db.UpdateAllowedAzureTenant(c.Request.Context(), tenant)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "tenant with this tenant_id already exists")
			return
		}
		log.Printf("Error updating Azure tenant %s: %v", id, err)
		respondInternalError(c, "internal server error")
		return
	}

	respondOK(c, result)
}

func (s *Server) deleteAzureTenant(c *gin.Context) {
	id := c.Param("id")

	// Look up the tenant to get its Azure tenant_id before deleting
	tenant, err := s.db.GetAllowedAzureTenant(c.Request.Context(), id)
	if err != nil {
		log.Printf("Error looking up Azure tenant %s: %v", id, err)
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
		log.Printf("Error deleting Azure tenant %s: %v", id, err)
		respondInternalError(c, "internal server error")
		return
	}

	// Ban all users from this tenant and revoke their sessions
	banned, banErr := s.db.BanUsersByTenantID(c.Request.Context(), tenant.TenantID, "Azure AD tenant removed")
	if banErr != nil {
		log.Printf("Warning: failed to ban users for tenant %s: %v", tenant.TenantID, banErr)
	} else if banned > 0 {
		log.Printf("Banned %d user(s) from deleted Azure tenant %s", banned, tenant.TenantID)
	}

	revoked, revokeErr := s.db.RevokeRefreshTokensByTenantID(c.Request.Context(), tenant.TenantID)
	if revokeErr != nil {
		log.Printf("Warning: failed to revoke refresh tokens for tenant %s: %v", tenant.TenantID, revokeErr)
	} else if revoked > 0 {
		log.Printf("Revoked %d refresh token(s) for users of deleted Azure tenant %s", revoked, tenant.TenantID)
	}

	respondDeleted(c, "azure tenant")
}
