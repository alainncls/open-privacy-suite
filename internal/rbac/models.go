// Package rbac provides role-based access control for the privacy proxy.
package rbac

import (
	"slices"
	"strings"
	"time"
)

// Claim represents a permission claim type for contract access.
type Claim string

const (
	ClaimRead    Claim = "read"    // eth_call, eth_estimateGas (view functions)
	ClaimWrite   Claim = "write"   // eth_sendTransaction (state-changing functions)
	ClaimAdmin   Claim = "admin"   // Full control, considered "owner" of the contract
	ClaimUpgrade Claim = "upgrade" // Can upgrade proxy contracts
	ClaimDeploy  Claim = "deploy"  // Can deploy new contracts (contract creation transactions)
)

// AllClaims returns all valid claims.
func AllClaims() []Claim {
	return []Claim{ClaimRead, ClaimWrite, ClaimAdmin, ClaimUpgrade, ClaimDeploy}
}

// MembershipSource indicates how a user obtained membership in a group.
type MembershipSource string

const (
	MembershipSourceAdmin      MembershipSource = "admin"
	MembershipSourceZKAttested MembershipSource = "zk_attested"
)

// Default IDs for seeded data (matching database migrations).
const (
	// DefaultOrgID is the ID of the default organization created on first run.
	DefaultOrgID = "00000000-0000-0000-0000-000000000001"
	// DefaultGroupID is the ID of the default group that new users are added to.
	DefaultGroupID = "00000000-0000-0000-0000-000000000001"
)

// Organization represents a top-level tenant.
type Organization struct {
	ID        string         `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Settings  map[string]any `json:"settings"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Group represents a hierarchical permission container within an organization.
// Note: Permissions come from GroupAccess and ContractGrants, not roles.
type Group struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	ParentID    *string   `json:"parent_id,omitempty"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Depth       int       `json:"depth"`
	Path        string    `json:"path"`         // Materialized path (e.g., "root.engineering.devops")
	IsOrgAdmin  bool      `json:"is_org_admin"` // If true, members get all claims on all contracts in the org
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Contract represents a first-class contract resource.
// "Ownership" is claims-based - a group with 'admin' claim is considered the owner.
type Contract struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"org_id"`
	Address          string         `json:"address"` // lowercase 0x-prefixed
	Name             string         `json:"name,omitempty"`
	DeployedByUserID *string        `json:"deployed_by_user_id,omitempty"`
	DeployedAt       *time.Time     `json:"deployed_at,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// ContractGrant links a group to a contract with specific claims.
type ContractGrant struct {
	ID         string    `json:"id"`
	ContractID string    `json:"contract_id"`
	GroupID    string    `json:"group_id"`
	Claims     []Claim   `json:"claims"`              // read, write, admin, upgrade
	Functions  []string  `json:"functions,omitempty"` // nil = all functions, or specific selectors
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// GroupAccess represents RPC method permissions and rate limits for a group.
type GroupAccess struct {
	ID             string    `json:"id"`
	GroupID        string    `json:"group_id"`
	AllowedMethods []string  `json:"allowed_methods"`
	DefaultClaims  []Claim   `json:"default_claims"` // Claims for unregistered contracts
	RateLimitRPS   *int      `json:"rate_limit_rps,omitempty"`
	RateLimitDaily *int      `json:"rate_limit_daily,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
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

// UserMembership links a user to a group.
// Note: No role_id - permissions come from group's access settings.
type UserMembership struct {
	ID              string           `json:"id"`
	UserID          string           `json:"user_id"`
	GroupID         string           `json:"group_id"`
	Source          MembershipSource `json:"source"`
	ZKCredentialRef string           `json:"zk_credential_ref,omitempty"`
	ExpiresAt       *time.Time       `json:"expires_at,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// ContractAccess represents access permissions for a specific contract.
type ContractAccess struct {
	Claims    []Claim  `json:"claims"`
	Functions []string `json:"functions,omitempty"` // nil = all functions allowed
}

// EffectivePermissions represents the computed permissions for a user in an organization.
type EffectivePermissions struct {
	ID             string                    `json:"id"`
	UserID         string                    `json:"user_id"`
	OrgID          string                    `json:"org_id"`
	AllowedMethods []string                  `json:"allowed_methods"`
	ContractAccess map[string]ContractAccess `json:"contract_access"` // address -> access
	DefaultClaims  []Claim                   `json:"default_claims"`  // Claims for unregistered contracts
	RateLimitRPS   *int                      `json:"rate_limit_rps,omitempty"`
	RateLimitDaily *int                      `json:"rate_limit_daily,omitempty"`
	ComputedAt     time.Time                 `json:"computed_at"`
	ExpiresAt      time.Time                 `json:"expires_at"`
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
	Allowed           bool               `json:"allowed"`
	Reason            string             `json:"reason,omitempty"`
	RateLimitRPS      *int               `json:"rate_limit_rps,omitempty"`
	RateLimitDaily    *int               `json:"rate_limit_daily,omitempty"`
	Claims            []Claim            `json:"claims,omitempty"`
	DeploymentInfo    *DeploymentInfo    `json:"deployment_info,omitempty"`     // Set for allowed deployments
	FactoryDeployInfo *FactoryDeployInfo `json:"factory_deploy_info,omitempty"` // Set for CREATE3 factory deploys
}

// DeploymentInfo contains information about an allowed deployment.
// This is used by the RPC layer to track pending deployments for proxy registration.
type DeploymentInfo struct {
	OrgID     string `json:"org_id"`
	IsProxy   bool   `json:"is_proxy"`
	ProxyType string `json:"proxy_type,omitempty"`
}

// FactoryDeployInfo contains information about a CREATE3 factory deployment.
// This is used to auto-register contracts after successful factory deploys.
type FactoryDeployInfo struct {
	OrgID         string `json:"org_id"`          // Organization that owns the deployment
	TargetAddress string `json:"target_address"`  // Computed CREATE3 address
	FactoryAddr   string `json:"factory_address"` // Factory contract address
	Salt          string `json:"salt"`            // Salt used for deployment
}

// GroupWithAccess combines a Group with its access settings.
type GroupWithAccess struct {
	Group  *Group       `json:"group"`
	Access *GroupAccess `json:"access"`
}

// UserWithMemberships combines a User with their group memberships.
type UserWithMemberships struct {
	User        *User             `json:"user"`
	Memberships []*UserMembership `json:"memberships"`
}

// MembershipWithDetails includes membership with group information.
type MembershipWithDetails struct {
	Membership *UserMembership `json:"membership"`
	Group      *Group          `json:"group"`
}

// ContractWithGrants combines a Contract with its grants.
type ContractWithGrants struct {
	Contract *Contract        `json:"contract"`
	Grants   []*ContractGrant `json:"grants"`
}

// ContractGrantWithGroup includes grant with group details.
type ContractGrantWithGroup struct {
	Grant *ContractGrant `json:"grant"`
	Group *Group         `json:"group"`
}

// HasMethod checks if the effective permissions allow a specific method.
func (e *EffectivePermissions) HasMethod(method string) bool {
	return slices.Contains(e.AllowedMethods, method)
}

// GetContractAccess returns the access for a specific contract address.
// If the contract is not registered, returns access based on default_claims.
func (e *EffectivePermissions) GetContractAccess(address string) *ContractAccess {
	addr := strings.ToLower(address)
	if access, ok := e.ContractAccess[addr]; ok {
		return &access
	}
	// Return access based on default claims for unregistered contracts
	if len(e.DefaultClaims) > 0 {
		return &ContractAccess{
			Claims:    e.DefaultClaims,
			Functions: nil, // All functions allowed for default
		}
	}
	return nil
}

// HasContractClaim checks if the user has a specific claim on a contract.
func (e *EffectivePermissions) HasContractClaim(address string, claim Claim) bool {
	access := e.GetContractAccess(address)
	if access == nil {
		return false
	}
	return slices.Contains(access.Claims, claim)
}

// HasFunctionSelector checks if a function selector is allowed for an address.
// If the contract has no specific function restrictions, all functions are allowed.
func (e *EffectivePermissions) HasFunctionSelector(address, selector string) bool {
	access := e.GetContractAccess(address)
	if access == nil {
		return false
	}

	// If no function restrictions defined, all functions are allowed
	if access.Functions == nil || len(access.Functions) == 0 {
		return true
	}

	// Check if selector is in the allowed list (case-insensitive)
	for _, allowed := range access.Functions {
		if strings.EqualFold(allowed, selector) {
			return true
		}
	}

	return false
}

// IsContractRegistered checks if a contract is explicitly registered in RBAC.
func (e *EffectivePermissions) IsContractRegistered(address string) bool {
	addr := strings.ToLower(address)
	_, ok := e.ContractAccess[addr]
	return ok
}

// HasAdminOnContract checks if the user has admin claim on a contract (i.e., is owner).
func (e *EffectivePermissions) HasAdminOnContract(address string) bool {
	return e.HasContractClaim(address, ClaimAdmin)
}

// HasContractAccess checks if the user has any access defined for a contract.
func (e *EffectivePermissions) HasContractAccess(address string) bool {
	addr := strings.ToLower(address)
	_, ok := e.ContractAccess[addr]
	return ok
}

// HasDefaultClaim checks if the user has a specific default claim.
func (e *EffectivePermissions) HasDefaultClaim(claim Claim) bool {
	return slices.Contains(e.DefaultClaims, claim)
}

// HasClaim checks if a ContractAccess includes a specific claim.
func (ca ContractAccess) HasClaim(claim Claim) bool {
	return slices.Contains(ca.Claims, claim)
}

// PreregisteredAddress represents a pre-registered CREATE3 deployment address.
// These addresses can be whitelisted before the actual contract is deployed,
// enabling upgradeable proxy patterns where implementation addresses need pre-approval.
type PreregisteredAddress struct {
	ID             string     `json:"id"`
	OrgID          string     `json:"org_id"`
	Address        string     `json:"address"`         // The pre-computed CREATE3 address (lowercase 0x-prefixed)
	Factory        string     `json:"factory"`         // The CREATE3 factory contract address
	Salt           []byte     `json:"salt"`            // The 32-byte salt used for address derivation
	Note           string     `json:"note,omitempty"`
	ConstructorABI string     `json:"constructor_abi,omitempty"` // Contract ABI JSON for constructor arg validation
	CreatedAt      time.Time  `json:"created_at"`
	UsedAt         *time.Time `json:"used_at,omitempty"` // Timestamp when the address was actually deployed to
}

// ManagedProxy represents a proxy contract that is tracked for upgrade validation.
// When a transaction targets a managed proxy with an upgrade selector, the upgrade
// validator ensures the new implementation is owned by the same organization.
type ManagedProxy struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	ProxyAddress string    `json:"proxy_address"` // The proxy contract address (lowercase 0x-prefixed)
	ProxyType    string    `json:"proxy_type"`    // Type of proxy (e.g., "transparent", "uups", "beacon")
	CurrentImpl  string    `json:"current_impl"`  // Current implementation address
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
