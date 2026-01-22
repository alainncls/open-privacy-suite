package server

import (
	"github.com/gin-gonic/gin"
)

// registerRBACRoutes registers RBAC admin API endpoints.
func (s *Server) registerRBACRoutes(api *gin.RouterGroup) {
	// Organizations
	api.GET("/orgs", s.listOrganizations)
	api.POST("/orgs", s.createOrganization)
	api.GET("/orgs/:org_id", s.getOrganization)
	api.PUT("/orgs/:org_id", s.updateOrganization)

	// Groups
	api.GET("/orgs/:org_id/groups", s.listGroups)
	api.POST("/orgs/:org_id/groups", s.createGroup)
	api.GET("/orgs/:org_id/groups/:group_id", s.getGroup)
	api.PUT("/orgs/:org_id/groups/:group_id", s.updateGroup)
	api.DELETE("/orgs/:org_id/groups/:group_id", s.deleteGroup)

	// Group Access (replaces old permissions and roles)
	api.GET("/orgs/:org_id/groups/:group_id/access", s.getGroupAccess)
	api.PUT("/orgs/:org_id/groups/:group_id/access", s.setGroupAccess)

	// Contracts
	api.GET("/orgs/:org_id/contracts", s.listContracts)
	api.POST("/orgs/:org_id/contracts", s.createContract)
	api.GET("/orgs/:org_id/contracts/:address", s.getContract)
	api.PUT("/orgs/:org_id/contracts/:address", s.updateContract)
	api.DELETE("/orgs/:org_id/contracts/:address", s.deleteContract)

	// Contract Grants
	api.GET("/orgs/:org_id/contracts/:address/grants", s.listContractGrants)
	api.POST("/orgs/:org_id/contracts/:address/grants", s.createContractGrant)
	api.PUT("/orgs/:org_id/contracts/:address/grants/:group_id", s.updateContractGrant)
	api.DELETE("/orgs/:org_id/contracts/:address/grants/:group_id", s.deleteContractGrant)

	// Users
	api.GET("/users", s.listRBACUsers)
	api.GET("/users/:user_id", s.getRBACUser)
	api.PUT("/users/:user_id", s.updateRBACUser)
	api.GET("/users/:user_id/linked-addresses", s.getUserLinkedAddresses)

	// Memberships
	api.GET("/users/:user_id/memberships", s.listUserMemberships)
	api.POST("/users/:user_id/memberships", s.createUserMembership)
	api.DELETE("/users/:user_id/memberships/:membership_id", s.deleteUserMembership)

	// Debugging
	api.GET("/users/:user_id/effective-permissions", s.getEffectivePermissions)
	api.POST("/access/check", s.checkAccessAPI)
	api.GET("/cache/stats", s.getCacheStats)
}
