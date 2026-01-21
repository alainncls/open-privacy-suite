// Package rbac provides role-based access control for the privacy proxy.
package rbac

import (
	"slices"
	"strings"
	"time"
)

// Claim represents a permission claim type.
type Claim string

const (
	ClaimReader   Claim = "reader"
	ClaimWriter   Claim = "writer"
	ClaimDeployer Claim = "deployer"
	ClaimAdmin    Claim = "admin"
	ClaimUpgrade  Claim = "upgrade"
)

// MembershipSource indicates how a user obtained membership in a group.
type MembershipSource string

const (
	MembershipSourceAdmin      MembershipSource = "admin"
	MembershipSourceZKAttested MembershipSource = "zk_attested"
)

// Organization represents a top-level tenant.
type Organization struct {
	ID        string            `json:"id"`
	Slug      string            `json:"slug"`
	Name      string            `json:"name"`
	Settings  map[string]any    `json:"settings"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Group represents a hierarchical permission container within an organization.
type Group struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	ParentID    *string   `json:"parent_id,omitempty"`
	RoleID      *string   `json:"role_id,omitempty"` // Assigned role - all members inherit this role's permissions
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Depth       int       `json:"depth"`
	Path        string    `json:"path"` // Materialized path (e.g., "root.engineering.devops")
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Role represents a named permission set with claims and allowed methods.
type Role struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Claims       []Claim   `json:"claims"`
	AllowMethods []string  `json:"allow_methods"` // Allowed RPC methods for this role
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// GroupPermissions represents the permissions assigned to a group.
type GroupPermissions struct {
	ID               string              `json:"id"`
	GroupID          string              `json:"group_id"`
	AllowMethods     []string            `json:"allow_methods"`
	AllowAddresses   []string            `json:"allow_addresses"`
	OwnedAddresses   []string            `json:"owned_addresses"`
	AddressFunctions map[string][]string `json:"address_functions,omitempty"` // address -> allowed function selectors
	RateLimitRPS     *int                `json:"rate_limit_rps,omitempty"`
	RateLimitDaily   *int                `json:"rate_limit_daily,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

// User represents a user in the RBAC system.
type User struct {
	ID         string         `json:"id"`
	ExternalID string         `json:"external_id"` // User's DID
	KYC        bool           `json:"kyc"`
	Banned     bool           `json:"banned"`
	Note       string         `json:"note,omitempty"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// UserMembership links a user to a group with a specific role.
type UserMembership struct {
	ID              string           `json:"id"`
	UserID          string           `json:"user_id"`
	GroupID         string           `json:"group_id"`
	RoleID          *string          `json:"role_id,omitempty"`
	Source          MembershipSource `json:"source"`
	ZKCredentialRef string           `json:"zk_credential_ref,omitempty"`
	ExpiresAt       *time.Time       `json:"expires_at,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// ContractOwnership tracks deployed contracts and their owner groups.
type ContractOwnership struct {
	ID               string         `json:"id"`
	ContractAddress  string         `json:"contract_address"`
	OrgID            string         `json:"org_id"`
	OwnerGroupID     string         `json:"owner_group_id"`
	DeployedByUserID *string        `json:"deployed_by_user_id,omitempty"`
	DeployedAt       *time.Time     `json:"deployed_at,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// EffectivePermissions represents the computed permissions for a user in an organization.
type EffectivePermissions struct {
	ID               string              `json:"id"`
	UserID           string              `json:"user_id"`
	OrgID            string              `json:"org_id"`
	AllowMethods     []string            `json:"allow_methods"`
	AllowAddresses   []string            `json:"allow_addresses"`
	OwnedAddresses   []string            `json:"owned_addresses"`
	AddressFunctions map[string][]string `json:"address_functions,omitempty"` // address -> allowed function selectors
	Claims           []Claim             `json:"claims"`
	RateLimitRPS     *int                `json:"rate_limit_rps,omitempty"`
	RateLimitDaily   *int                `json:"rate_limit_daily,omitempty"`
	ComputedAt       time.Time           `json:"computed_at"`
	ExpiresAt        time.Time           `json:"expires_at"`
}

// AuditLogEntry represents an entry in the RBAC audit log.
type AuditLogEntry struct {
	ID              int64          `json:"id"`
	ActorID         *string        `json:"actor_id,omitempty"`
	ActorExternalID string         `json:"actor_external_id,omitempty"`
	Action          string         `json:"action"` // create, update, delete, assign, revoke
	ResourceType    string         `json:"resource_type"`
	ResourceID      *string        `json:"resource_id,omitempty"`
	ResourceName    string         `json:"resource_name,omitempty"`
	OldValue        map[string]any `json:"old_value,omitempty"`
	NewValue        map[string]any `json:"new_value,omitempty"`
	IPAddress       string         `json:"ip_address,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

// AccessCheckRequest represents a request to check access permissions.
type AccessCheckRequest struct {
	UserExternalID   string  `json:"user_external_id"`
	OrgSlug          string  `json:"org_slug,omitempty"` // Optional, defaults to "default"
	Method           string  `json:"method"`
	Params           []any   `json:"params,omitempty"`            // JSON-RPC params for Multicall detection
	TargetAddress    string  `json:"target_address,omitempty"`    // Target address (contract or EOA)
	FunctionSelector string  `json:"function_selector,omitempty"` // First 4 bytes of calldata (e.g., "0xa9059cbb")
	RequiredClaims   []Claim `json:"required_claims,omitempty"`
}

// AccessCheckResult represents the result of an access check.
type AccessCheckResult struct {
	Allowed        bool     `json:"allowed"`
	Reason         string   `json:"reason,omitempty"`
	RateLimitRPS   *int     `json:"rate_limit_rps,omitempty"`
	RateLimitDaily *int     `json:"rate_limit_daily,omitempty"`
	Claims         []Claim  `json:"claims,omitempty"`
}

// GroupWithPermissions combines a Group with its associated permissions.
type GroupWithPermissions struct {
	Group       *Group            `json:"group"`
	Permissions *GroupPermissions `json:"permissions"`
}

// UserWithMemberships combines a User with their group memberships.
type UserWithMemberships struct {
	User        *User             `json:"user"`
	Memberships []*UserMembership `json:"memberships"`
}

// MembershipWithDetails includes membership with group and role information.
type MembershipWithDetails struct {
	Membership *UserMembership `json:"membership"`
	Group      *Group          `json:"group"`
	Role       *Role           `json:"role,omitempty"`
}

// HasClaim checks if the effective permissions include a specific claim.
func (e *EffectivePermissions) HasClaim(claim Claim) bool {
	return slices.Contains(e.Claims, claim)
}

// HasMethod checks if the effective permissions allow a specific method.
func (e *EffectivePermissions) HasMethod(method string) bool {
	return slices.Contains(e.AllowMethods, method)
}

// HasAddress checks if the effective permissions allow a specific address.
// If AllowAddresses is empty, all addresses are allowed (no restriction).
func (e *EffectivePermissions) HasAddress(address string) bool {
	// Empty allow_addresses means no address restriction - allow all
	if len(e.AllowAddresses) == 0 {
		return true
	}
	return slices.Contains(e.AllowAddresses, address)
}

// OwnsAddress checks if the effective permissions include ownership of an address.
func (e *EffectivePermissions) OwnsAddress(address string) bool {
	return slices.Contains(e.OwnedAddresses, address)
}

// HasFunctionSelector checks if a function selector is allowed for an address.
// If the address has no specific function restrictions, all functions are allowed.
// The selector should be the first 4 bytes of calldata (e.g., "0xa9059cbb" for transfer).
func (e *EffectivePermissions) HasFunctionSelector(address, selector string) bool {
	// If no function restrictions defined, all functions are allowed
	if e.AddressFunctions == nil || len(e.AddressFunctions) == 0 {
		return true
	}

	// Check if this specific address has function restrictions
	allowedSelectors, hasRestrictions := e.AddressFunctions[address]
	if !hasRestrictions {
		// Address not in the map, all functions allowed
		return true
	}

	// Empty list means no functions allowed
	if len(allowedSelectors) == 0 {
		return false
	}

	// Check if selector is in the allowed list (case-insensitive)
	for _, allowed := range allowedSelectors {
		if strings.EqualFold(allowed, selector) {
			return true
		}
	}

	return false
}
