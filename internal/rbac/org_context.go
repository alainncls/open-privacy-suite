package rbac

import (
	"context"
	"fmt"
	"strings"

	"privacy-proxy/internal/evm/precompile"
)

// OrgContext encapsulates organization-scoped access decisions.
// It provides a unified interface for all cross-org isolation checks,
// pre-loading user membership data once for efficient reuse.
//
// Usage:
//
//	orgCtx, err := NewOrgContext(ctx, store, user, targetAddress)
//	if err != nil { return err }  // Cross-org violation detected early
//
//	// Later, for additional address checks:
//	err = orgCtx.CheckAddressInScope(ctx, anotherAddress)
type OrgContext struct {
	org        *Organization   // The determined org context (can be nil for public/no-target)
	user       *User           // The authenticated user
	userOrgIDs map[string]bool // Pre-loaded: all orgs user belongs to
	store      Store           // For additional lookups
}

// NewOrgContext creates an OrgContext from a target address.
// This determines the org context based on contract ownership:
//   - If target is owned by an org the user belongs to, use that org
//   - If target is public (not owned by any org), org is nil
//   - If target is owned by an org the user does NOT belong to, returns error
//
// Parameters:
//   - ctx: Context for database calls
//   - store: RBAC store for lookups
//   - user: The authenticated user
//   - targetAddress: The target contract address (can be empty)
//
// Returns:
//   - OrgContext if valid
//   - Error if cross-org isolation is violated
func NewOrgContext(ctx context.Context, store Store, user *User, targetAddress string) (*OrgContext, error) {
	// Pre-load user's org memberships
	userOrgIDs, err := GetUserOrgIDs(ctx, store, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	oc := &OrgContext{
		user:       user,
		userOrgIDs: userOrgIDs,
		store:      store,
	}

	// If no target address, org context remains nil (will use default org later)
	if targetAddress == "" {
		return oc, nil
	}

	// Determine org from target address ownership
	addr := strings.ToLower(strings.TrimSpace(targetAddress))
	ownerOrgID, err := store.GetContractOwnerOrgID(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get contract owner: %w", err)
	}

	if ownerOrgID == "" {
		// Contract is public (not owned by any org)
		return oc, nil
	}

	// Contract is owned by an org - verify user is a member
	if !userOrgIDs[ownerOrgID] {
		return nil, fmt.Errorf(ErrContractAccessDenied)
	}

	// User is a member - set the org context
	org, err := store.GetOrganization(ctx, ownerOrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	oc.org = org

	return oc, nil
}

// NewOrgContextForOrg creates an OrgContext for an explicit org.
// Used when the organization is already known (e.g., deployments using user's default org).
func NewOrgContextForOrg(ctx context.Context, store Store, user *User, orgID string) (*OrgContext, error) {
	// Pre-load user's org memberships
	userOrgIDs, err := GetUserOrgIDs(ctx, store, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	// Verify user is a member of the specified org
	if !userOrgIDs[orgID] {
		return nil, fmt.Errorf("user is not a member of organization %s", orgID)
	}

	org, err := store.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return &OrgContext{
		org:        org,
		user:       user,
		userOrgIDs: userOrgIDs,
		store:      store,
	}, nil
}

// OrgID returns the organization ID, or empty string if public context.
func (oc *OrgContext) OrgID() string {
	if oc.org == nil {
		return ""
	}
	return oc.org.ID
}

// Org returns the organization, or nil if public context.
func (oc *OrgContext) Org() *Organization {
	return oc.org
}

// User returns the user.
func (oc *OrgContext) User() *User {
	return oc.user
}

// UserOrgIDs returns the set of org IDs the user belongs to.
func (oc *OrgContext) UserOrgIDs() map[string]bool {
	return oc.userOrgIDs
}

// IsPublicContext returns true if no org context was determined.
// This happens when the target address is not owned by any org.
func (oc *OrgContext) IsPublicContext() bool {
	return oc.org == nil
}

// UserBelongsToOrg returns true if the user belongs to the determined org.
// Always returns true for public context (no org = no restriction).
func (oc *OrgContext) UserBelongsToOrg() bool {
	if oc.org == nil {
		return true
	}
	return oc.userOrgIDs[oc.org.ID]
}

// CheckAddressInScope validates that an address is accessible in this org context.
// Used for operations that interact with multiple addresses (e.g., eth_getLogs).
//
// Rules:
//   - If address is in current org context: allowed
//   - If address is in another org user belongs to: allowed (multi-org support)
//   - If address is in an org user does NOT belong to: denied
//   - If address is public (not registered to any org): allowed
func (oc *OrgContext) CheckAddressInScope(ctx context.Context, address string) error {
	addr := strings.ToLower(strings.TrimSpace(address))
	if addr == "" {
		return nil // No address to check
	}

	ownerOrgID, err := oc.store.GetContractOwnerOrgID(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to check contract owner: %w", err)
	}

	if ownerOrgID == "" {
		// Not owned by any org — only precompiles are allowed.
		// All other unregistered addresses are private by default.
		if precompile.IsPrecompileAddress(addr) {
			return nil
		}
		return fmt.Errorf(ErrContractAccessDenied)
	}

	// Contract is owned by an org - check if user is a member
	if !oc.userOrgIDs[ownerOrgID] {
		return fmt.Errorf(ErrContractAccessDenied)
	}

	return nil
}

// CheckMultiAddressesInScope validates multiple addresses are all in scope.
// Returns error on first cross-org violation found.
func (oc *OrgContext) CheckMultiAddressesInScope(ctx context.Context, addresses []string) error {
	for _, addr := range addresses {
		if err := oc.CheckAddressInScope(ctx, addr); err != nil {
			return err
		}
	}
	return nil
}

// CheckDefaultClaimsAllowed validates whether default_claims can be used for an address.
// This enforces that default_claims only apply to truly unregistered/public contracts.
// Registered contracts (even in user's own org) require explicit grants.
//
// Parameters:
//   - ctx: Context
//   - address: The target address
//   - hasExplicitAccess: Whether user has explicit ContractAccess for this address
//
// Returns:
//   - nil if default_claims can be used (contract is not registered anywhere)
//   - error if the contract is registered to any org (requires explicit grant)
func (oc *OrgContext) CheckDefaultClaimsAllowed(ctx context.Context, address string, hasExplicitAccess bool, claims []Claim) error {
	if hasExplicitAccess {
		// User has explicit access via grant - no need to check default_claims
		return nil
	}

	addr := strings.ToLower(strings.TrimSpace(address))
	if addr == "" {
		return nil
	}

	// Check which org owns this contract
	ownerOrgID, err := oc.store.GetContractOwnerOrgID(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to check contract ownership: %w", err)
	}

	if ownerOrgID == "" {
		// Not registered anywhere — only precompiles are truly public.
		// All other unregistered addresses are private by default.
		if precompile.IsPrecompileAddress(addr) {
			return nil
		}
		return fmt.Errorf(ErrContractAccessDenied)
	}

	// Contract belongs to a different org - deny
	if !oc.userOrgIDs[ownerOrgID] {
		return fmt.Errorf(ErrContractAccessDenied)
	}

	// Contract is in user's own org - deploy/admin users can access via default claims
	if hasClaim(claims, ClaimDeploy) || hasClaim(claims, ClaimAdmin) {
		return nil
	}

	// Read/write-only users need explicit grants for registered contracts
	return fmt.Errorf(ErrContractAccessDenied)
}

// ValidateFactoryCallOrgs checks factory calls against all orgs the user belongs to.
// Returns the validation result if this is a factory call, or nil if not.
// If multiple orgs have the same factory configured, checks preregistration against
// all of them and returns success if ANY org has the address preregistered.
func (oc *OrgContext) ValidateFactoryCallOrgs(
	ctx context.Context,
	targetAddr string,
	calldata []byte,
	validator *FactoryCallValidator,
) (*FactoryCallValidationResult, error) {
	var lastFailedResult *FactoryCallValidationResult

	// Check each org the user is a member of
	for orgID := range oc.userOrgIDs {
		org, err := oc.store.GetOrganization(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to get organization: %w", err)
		}
		if org == nil {
			continue
		}

		factoryAddress := GetOrgFactoryAddress(org)
		if factoryAddress == "" {
			continue
		}

		// Check if target matches this org's factory
		result, err := validator.ValidateFactoryCall(ctx, org.ID, factoryAddress, targetAddr, calldata)
		if err != nil {
			return nil, fmt.Errorf("failed to validate factory call for org %s: %w", org.Slug, err)
		}

		// If this is a factory call to this org's factory
		if result.IsFactoryCall && result.IsDeployCall {
			// If allowed, return success immediately
			if result.Allowed {
				result.OrgID = org.ID
				return result, nil
			}
			// If denied, save the result but continue checking other orgs
			// (in case the address is preregistered for another org with the same factory)
			lastFailedResult = result
		}
	}

	// If we found a factory call but it was denied for all orgs, return the last failed result
	if lastFailedResult != nil {
		return lastFailedResult, nil
	}

	// Not a factory call for any of user's orgs
	return nil, nil
}

// GetUserOrgIDs returns the set of organization IDs the user belongs to.
func GetUserOrgIDs(ctx context.Context, store Store, userID string) (map[string]bool, error) {
	memberships, err := store.ListUserMembershipsWithDetails(ctx, userID)
	if err != nil {
		return nil, err
	}

	orgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			orgIDs[m.Group.OrgID] = true
		}
	}

	return orgIDs, nil
}
