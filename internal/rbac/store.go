package rbac

import (
	"context"
)

// Store defines the interface for RBAC data operations.
type Store interface {
	// Organization operations
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	ListOrganizations(ctx context.Context) ([]*Organization, error)
	DeleteOrganization(ctx context.Context, id string) error

	// Group operations
	CreateGroup(ctx context.Context, group *Group) error
	GetGroup(ctx context.Context, id string) (*Group, error)
	GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error)
	UpdateGroup(ctx context.Context, group *Group) error
	ListGroups(ctx context.Context, orgID string) ([]*Group, error)
	ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error)
	GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) // Returns groups from root to the specified group
	DeleteGroup(ctx context.Context, id string) error

	// Group Access operations (replaces roles.allow_methods and group_permissions)
	CreateGroupAccess(ctx context.Context, access *GroupAccess) error
	GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error)
	UpdateGroupAccess(ctx context.Context, access *GroupAccess) error
	DeleteGroupAccess(ctx context.Context, groupID string) error

	// Contract operations
	CreateContract(ctx context.Context, contract *Contract) error
	GetContract(ctx context.Context, id string) (*Contract, error)
	GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error)
	UpdateContract(ctx context.Context, contract *Contract) error
	ListContracts(ctx context.Context, orgID string) ([]*Contract, error)
	DeleteContract(ctx context.Context, id string) error

	// Contract Grant operations
	CreateContractGrant(ctx context.Context, grant *ContractGrant) error
	GetContractGrant(ctx context.Context, id string) (*ContractGrant, error)
	GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*ContractGrant, error)
	UpdateContractGrant(ctx context.Context, grant *ContractGrant) error
	ListContractGrantsByContract(ctx context.Context, contractID string) ([]*ContractGrant, error)
	ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error)
	ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error)
	DeleteContractGrant(ctx context.Context, id string) error

	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByExternalID(ctx context.Context, externalID string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	DeleteUser(ctx context.Context, id string) error

	// Membership operations
	CreateMembership(ctx context.Context, membership *UserMembership) error
	GetMembership(ctx context.Context, id string) (*UserMembership, error)
	GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error)
	UpdateMembership(ctx context.Context, membership *UserMembership) error
	ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error)
	ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error)
	ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error)
	ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error)
	DeleteMembership(ctx context.Context, id string) error
	DeleteExpiredMemberships(ctx context.Context) (int64, error)

	// Effective Permissions Cache operations
	GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error)
	SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error
	InvalidateCacheForUser(ctx context.Context, userID string) error
	InvalidateCacheForOrg(ctx context.Context, orgID string) error
	InvalidateCacheForGroup(ctx context.Context, groupID string) error
	CleanupExpiredCache(ctx context.Context) (int64, error)

	// Audit Log operations
	CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error
	ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error)
	ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error)
}

// AuditAction constants for audit logging.
const (
	AuditActionCreate = "create"
	AuditActionUpdate = "update"
	AuditActionDelete = "delete"
	AuditActionAssign = "assign"
	AuditActionRevoke = "revoke"
)

// ResourceType constants for audit logging.
const (
	ResourceTypeOrganization = "organization"
	ResourceTypeGroup        = "group"
	ResourceTypeUser         = "user"
	ResourceTypeMembership   = "membership"
	ResourceTypeContract     = "contract"
	ResourceTypeGrant        = "grant"
	ResourceTypeAccess       = "access"
)
