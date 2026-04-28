// Package rbac provides role-based access control for the privacy proxy.
package rbac

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"privacy-proxy/internal/evm/precompile"
)

// Claim represents a permission claim type for contract access.
type Claim string

const (
	ClaimRead    Claim = "read"    // Legacy — retained for DB compatibility; no longer used as a gate
	ClaimWrite   Claim = "write"   // Legacy — retained for DB compatibility; no longer used as a gate
	ClaimAdmin   Claim = "admin"   // Full control — implies deploy + upgrade
	ClaimUpgrade Claim = "upgrade" // Can upgrade proxy contracts
	ClaimDeploy  Claim = "deploy"  // Can deploy new contracts (contract creation transactions)
)

// AllClaims returns all valid claims.
func AllClaims() []Claim {
	return []Claim{ClaimRead, ClaimWrite, ClaimAdmin, ClaimUpgrade, ClaimDeploy}
}

// claimImplications defines which claims each claim implies.
// admin implies deploy+upgrade. Read/write access is determined by the method
// allowlist, not by claims — those are operational gates only.
var claimImplications = map[Claim][]Claim{
	ClaimAdmin:   {ClaimDeploy, ClaimUpgrade},
	ClaimDeploy:  {},
	ClaimUpgrade: {},
}

// OperationalClaims are the claims that serve as operation-level gates.
// Read/write access is determined by the method allowlist, not by claims.
var OperationalClaims = map[Claim]bool{
	ClaimDeploy:  true,
	ClaimUpgrade: true,
	ClaimAdmin:   true,
}

// FilterOperationalClaims removes read/write claims, keeping only
// operational claims (deploy, upgrade, admin). This is used when
// accepting claims from the frontend to strip legacy read/write values.
func FilterOperationalClaims(claims []Claim) []Claim {
	result := make([]Claim, 0, len(claims))
	for _, c := range claims {
		if OperationalClaims[c] {
			result = append(result, c)
		}
	}
	return result
}

// ExpandClaims expands claims according to the hierarchy:
//   - admin → deploy, upgrade
//
// Read/write are no longer claim-gated; the method allowlist is the source of truth.
// Returns a deduplicated, sorted slice.
func ExpandClaims(claims []Claim) []Claim {
	set := make(map[Claim]bool, len(claims))
	for _, c := range claims {
		set[c] = true
		for _, implied := range claimImplications[c] {
			set[implied] = true
		}
	}

	result := make([]Claim, 0, len(set))
	for c := range set {
		result = append(result, c)
	}
	slices.SortFunc(result, func(a, b Claim) int {
		return strings.Compare(string(a), string(b))
	})
	return result
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

type AuditRecord struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	ActorID   string    `json:"actor_id"` // User or API Key ID
	Action    string    `json:"action"`   // e.g., "create", "update", "delete"
	Resource  string    `json:"resource"` // The type of resource (e.g., "ContractGrant")
	TargetID  string    `json:"target_id"` // GroupID, UserID, ContractID depending on resource
	Details   any       `json:"details"`  // The actual object changes
	Timestamp time.Time `json:"timestamp"`
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
	Path        string    `json:"path"`          // Materialized path (e.g., "root.engineering.devops")
	IsOrgAdmin  bool      `json:"is_org_admin"`  // If true, members get all claims on all contracts in the org
	AutoCreated bool      `json:"auto_created"`  // Deprecated: always false for new groups. Column retained in DB for expand-only migration policy.
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
	ABI              string         `json:"abi,omitempty"` // Contract ABI JSON for function-level access control
	DeployedByUserID *string        `json:"deployed_by_user_id,omitempty"`
	DeployedAt       *time.Time     `json:"deployed_at,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// FunctionRule describes access to a single contract function selector,
// with optional parameter-level constraints.
type FunctionRule struct {
	Selector   string      `json:"selector"`
	ParamRules []ParamRule `json:"param_rules,omitempty"`
}

// ParamRule constrains a single ABI parameter of a function call or event.
type ParamRule struct {
	Index  int    `json:"index"`   // ABI parameter position (0-based)
	MustBe string `json:"must_be"` // "self" (caller's address) or "0x..." (literal hex value)
}

// EventRule describes access to a single event (identified by topic0 hash),
// with optional parameter-level constraints.
type EventRule struct {
	Topic0     string      `json:"topic0"`                // keccak256(EventName(paramTypes)) — 32-byte hex with 0x prefix
	Name       string      `json:"name"`                  // human-readable event name, from ABI
	ParamRules []ParamRule `json:"param_rules,omitempty"` // optional "self" constraints (reuse existing ParamRule)
}

// EventRulesField represents event access configuration for a contract grant.
// Three states:
//   - Wildcard ("*" in JSON) = all events visible
//   - Deny (null or [] in JSON) = no events visible (fail-closed)
//   - Allowlist ([{...}] in JSON) = only listed events visible
type EventRulesField struct {
	Wildcard bool        // true when the JSON value is the string "*"
	Rules    []EventRule // allowlist rules; only meaningful when Wildcard is false
}

// IsWildcard returns true if all events are visible (wildcard mode).
func (f EventRulesField) IsWildcard() bool { return f.Wildcard }

// IsDeny returns true if no events are visible (deny mode).
func (f EventRulesField) IsDeny() bool { return !f.Wildcard && len(f.Rules) == 0 }

// GetRules returns the allowlist rules. Returns nil for wildcard or deny states.
func (f EventRulesField) GetRules() []EventRule {
	if f.Wildcard {
		return nil
	}
	return f.Rules
}

// MarshalJSON encodes the EventRulesField to JSON:
//   - Wildcard → "*" (quoted string)
//   - Deny (nil/empty rules) → null
//   - Allowlist → JSON array of EventRule
func (f EventRulesField) MarshalJSON() ([]byte, error) {
	if f.Wildcard {
		return json.Marshal("*")
	}
	if len(f.Rules) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(f.Rules)
}

// UnmarshalJSON decodes JSON into EventRulesField:
//   - "*" string → Wildcard=true
//   - null → Wildcard=false, Rules=nil (deny)
//   - [] → Wildcard=false, Rules=nil (deny)
//   - [{...}] → Wildcard=false, Rules=parsed
func (f *EventRulesField) UnmarshalJSON(data []byte) error {
	// Handle null
	if string(data) == "null" {
		f.Wildcard = false
		f.Rules = nil
		return nil
	}

	// Try string first (for "*")
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "*" {
			f.Wildcard = true
			f.Rules = nil
			return nil
		}
		return fmt.Errorf("invalid event_rules string: %q (only \"*\" is supported)", s)
	}

	// Try array
	var rules []EventRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("event_rules must be \"*\", null, or an array: %w", err)
	}

	f.Wildcard = false
	if len(rules) == 0 {
		f.Rules = nil // empty array = deny (same as null)
	} else {
		f.Rules = rules
	}
	return nil
}

// ContractGrant links a group to a contract, enabling access.
// The group's claims (from GroupAccess) apply to this contract.
// Functions can optionally restrict which contract functions are accessible.
// EventRules can optionally restrict which event logs are visible.
// Claims are inherited from the group's GroupAccess.claims - grants just link groups to contracts.
type ContractGrant struct {
	ID         string           `json:"id"`
	ContractID string           `json:"contract_id"`
	GroupID    string           `json:"group_id"`
	Functions  []FunctionRule   `json:"functions,omitempty"` // nil = all functions, or structured rules with optional param constraints
	EventRules *EventRulesField `json:"event_rules"`        // nil = deny, wildcard = all events, allowlist = specific events
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// GroupAccess represents RPC method permissions and rate limits for a group.
// AllowedMethods controls which RPC methods the group can call (the method allowlist).
// Claims are operational gates: only deploy, upgrade, and admin are meaningful.
// Read/write access is determined by AllowedMethods, not claims.
type GroupAccess struct {
	ID             string    `json:"id"`
	GroupID        string    `json:"group_id"`
	AllowedMethods []string  `json:"allowed_methods"`
	Claims         []Claim   `json:"claims"` // Operational claims: deploy, upgrade, admin
	RateLimitRPS     *int      `json:"rate_limit_rps,omitempty"`     // Deprecated: rate limiting moved to RPC proxy
	RateLimitDaily   *int      `json:"rate_limit_daily,omitempty"`   // Deprecated: rate limiting moved to RPC proxy
	RPCAPIKey        *string   `json:"rpc_api_key,omitempty"`        // API key for upstream RPC proxy authentication
	RPCAPIKeyHeader  string    `json:"rpc_api_key_header,omitempty"` // Header name for the upstream RPC API key (default "Authorization")
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	// Computed fields (not stored in DB, populated by handlers for child groups)
	EffectiveClaims  []Claim `json:"effective_claims,omitempty"`
	NarrowedByParent bool    `json:"narrowed_by_parent,omitempty"`
}

// User represents a user in the RBAC system.
type User struct {
	ID           string         `json:"id"`
	ExternalID   string         `json:"external_id"` // User's DID
	KYC          bool           `json:"kyc"`
	Banned       bool           `json:"banned"`
	Note         string         `json:"note,omitempty"`
	AuthTenantID *string        `json:"auth_tenant_id,omitempty"` // Azure AD tenant ID (nil for Privado users)
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
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
	Claims     []Claim          `json:"claims"`
	Functions  []FunctionRule   `json:"functions,omitempty"` // nil = all functions allowed
	EventRules *EventRulesField `json:"event_rules"`        // nil = deny, wildcard = all events, allowlist = specific events
}

// EffectivePermissions represents the computed permissions for a user in an organization.
// Claims are the user's capabilities from their group memberships.
// ContractAccess maps registered contract addresses to their access settings.
type EffectivePermissions struct {
	ID             string                    `json:"id"`
	UserID         string                    `json:"user_id"`
	OrgID          string                    `json:"org_id"`
	AllowedMethods []string                  `json:"allowed_methods"`
	ContractAccess map[string]ContractAccess `json:"contract_access"` // address -> access
	Claims         []Claim                   `json:"claims"`          // User's capabilities from groups
	RateLimitRPS    *int                      `json:"rate_limit_rps,omitempty"`
	RateLimitDaily  *int                      `json:"rate_limit_daily,omitempty"`
	RPCAPIKey       string                    `json:"-"` // Per-group upstream RPC API key (excluded from JSON — sensitive)
	RPCAPIKeyHeader string                    `json:"-"` // Per-group header name for RPC API key (empty = use config default)
	ComputedAt      time.Time                 `json:"computed_at"`
	ExpiresAt       time.Time                 `json:"expires_at"`
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
	OrgSlug          string  `json:"org_slug,omitempty"` // Optional org slug (deprecated, use OrgID)
	OrgID            string  `json:"org_id,omitempty"`   // Optional org ID for explicit org selection
	Method           string  `json:"method"`             // Original JSON-RPC method name (used for RBAC allowlist)
	AccessMethod     string  `json:"-"`                  // Resolved method for access control (alias target). Empty = same as Method.
	Params           []any   `json:"params,omitempty"`            // JSON-RPC params for Multicall detection
	TargetAddress    string  `json:"target_address,omitempty"`    // Target address (contract or EOA)
	FunctionSelector string  `json:"function_selector,omitempty"` // First 4 bytes of calldata (e.g., "0xa9059cbb")
	Calldata         []byte  `json:"-"`                           // Raw calldata bytes for parameter validation (not serialized)
	RequiredClaims   []Claim `json:"required_claims,omitempty"`
}

// EffectiveMethod returns the method name to use for access control decisions.
// Returns AccessMethod if set (for aliased chain-specific methods like linea_estimateGas
// → eth_estimateGas), otherwise returns Method.
func (r *AccessCheckRequest) EffectiveMethod() string {
	if r.AccessMethod != "" {
		return r.AccessMethod
	}
	return r.Method
}

// AccessCheckResult represents the result of an access check.
type AccessCheckResult struct {
	Allowed           bool               `json:"allowed"`
	AuthRequired      bool               `json:"auth_required,omitempty"`       // True when denial is due to missing authentication (401 vs 403)
	Reason            string             `json:"reason,omitempty"`
	OrgID             string             `json:"org_id,omitempty"`              // Resolved organization ID
	UserID            string             `json:"user_id,omitempty"`             // Internal user ID (UUID)
	RateLimitRPS      *int               `json:"rate_limit_rps,omitempty"`      // Deprecated: rate limiting moved to RPC proxy
	RateLimitDaily    *int               `json:"rate_limit_daily,omitempty"`    // Deprecated: rate limiting moved to RPC proxy
	RPCAPIKey         string             `json:"-"`                             // API key for upstream RPC proxy (excluded from JSON — sensitive)
	RPCAPIKeyHeader   string             `json:"-"`                             // Header name for upstream RPC API key (empty = use config default)
	Claims            []Claim            `json:"claims,omitempty"`
	DeploymentInfo *DeploymentInfo `json:"deployment_info,omitempty"` // Set for allowed deployments
}

// DeploymentInfo contains information about an allowed deployment.
// This is used by the RPC layer to track pending deployments for proxy registration.
type DeploymentInfo struct {
	OrgID     string `json:"org_id"`
	IsProxy   bool   `json:"is_proxy"`
	ProxyType string `json:"proxy_type,omitempty"`
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

// GroupSummary is a lightweight representation of a group for summary responses.
type GroupSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ContractGrantSummary contains the count of grants and the groups assigned to a contract.
type ContractGrantSummary struct {
	Count  int            `json:"count"`
	Groups []GroupSummary `json:"groups"`
}

// HasMethod checks if the effective permissions allow a specific method.
// "*" in AllowedMethods means all methods are permitted (used by admin auto-grant).
func (e *EffectivePermissions) HasMethod(method string) bool {
	return slices.Contains(e.AllowedMethods, "*") || slices.Contains(e.AllowedMethods, method)
}

// GetContractAccess returns the access for a specific contract address.
// For registered contracts, returns the explicit access from ContractAccess.
// For EVM precompiles (0x01-0x09), returns read-only access (precompiles are
// always accessible since they are built into the EVM).
// For all other unregistered addresses, returns nil (deny). All contracts are
// private by default — only explicit grants or org membership grant access.
// The caller (access.go) enforces cross-org isolation: contracts registered
// to a different org are denied regardless of claims.
func (e *EffectivePermissions) GetContractAccess(address string) *ContractAccess {
	addr := strings.ToLower(address)
	if access, ok := e.ContractAccess[addr]; ok {
		return &access
	}
	// Precompiles (0x01-0x09) are always accessible — they are native EVM functions.
	if precompile.IsPrecompileAddress(addr) {
		return &ContractAccess{
			Claims:    nil, // No operational claims needed; access is implied by the entry existing.
			Functions: nil,
		}
	}
	// All other unregistered addresses are private by default — deny.
	return nil
}

// hasClaim checks if a specific claim exists in a claims slice.
func hasClaim(claims []Claim, target Claim) bool {
	return slices.Contains(claims, target)
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

	// nil = unrestricted (all functions allowed)
	if access.Functions == nil {
		return true
	}
	// Non-nil but empty = explicitly no functions allowed (deny all)
	if len(access.Functions) == 0 {
		return false
	}

	// Check if selector is in the allowed list (case-insensitive)
	for _, rule := range access.Functions {
		if strings.EqualFold(rule.Selector, selector) {
			return true
		}
	}

	return false
}

// GetFunctionRule returns the FunctionRule for a specific selector on a contract.
// Returns nil if no specific rule exists (selector is allowed without constraints or not found).
func (e *EffectivePermissions) GetFunctionRule(address, selector string) *FunctionRule {
	access := e.GetContractAccess(address)
	if access == nil {
		return nil
	}
	if access.Functions == nil {
		return nil // nil = unrestricted, no specific rule
	}
	if len(access.Functions) == 0 {
		return nil // empty = deny all, no matching rule (HasFunctionSelector handles denial)
	}
	for i := range access.Functions {
		if strings.EqualFold(access.Functions[i].Selector, selector) {
			return &access.Functions[i]
		}
	}
	return nil
}

// GetEventRules returns the event rules for a specific contract address.
// Returns nil if no event rules are configured (deny all).
func (e *EffectivePermissions) GetEventRules(address string) *EventRulesField {
	access := e.GetContractAccess(address)
	if access == nil {
		return nil
	}
	return access.EventRules
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
	return slices.Contains(e.Claims, claim)
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


