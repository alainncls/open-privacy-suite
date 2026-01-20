package rbac

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Resolver computes effective permissions for users.
type Resolver struct {
	store    Store
	cacheTTL time.Duration
}

// NewResolver creates a new permission resolver.
func NewResolver(store Store, cacheTTL time.Duration) *Resolver {
	return &Resolver{
		store:    store,
		cacheTTL: cacheTTL,
	}
}

// ResolvePermissions computes the effective permissions for a user in an organization.
// It first checks the cache, then computes permissions if not cached.
func (r *Resolver) ResolvePermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	// Check cache first
	cached, err := r.store.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if cached != nil {
		return cached, nil
	}

	// Compute permissions
	perms, err := r.computePermissions(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if err := r.store.SetCachedPermissions(ctx, perms); err != nil {
		// Log error but don't fail - caching is optional
		_ = err
	}

	return perms, nil
}

// computePermissions calculates effective permissions using restrictive inheritance.
//
// Algorithm:
// 1. Get user's memberships in the org
// 2. For each membership, traverse group hierarchy (root → leaf)
// 3. At each level, apply INTERSECTION for methods and contracts
// 4. Apply UNION for owned contracts (ownership propagates down)
// 5. Take MINIMUM for rate limits (most restrictive wins)
// 6. Merge permissions across multiple group memberships (UNION)
// 7. Collect claims from assigned roles
func (r *Resolver) computePermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	// Get user's memberships in this org with details
	memberships, err := r.store.ListUserMembershipsInOrg(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	if len(memberships) == 0 {
		// User has no memberships - return empty permissions
		return &EffectivePermissions{
			ID:                uuid.New().String(),
			UserID:            userID,
			OrgID:             orgID,
			AllowMethods:      []string{},
			AllowContracts:    []string{},
			OwnedContracts:    []string{},
			ContractFunctions: make(map[string][]string),
			Claims:            []Claim{},
			ComputedAt:        time.Now(),
			ExpiresAt:         time.Now().Add(r.cacheTTL),
		}, nil
	}

	// Track final merged permissions across all memberships
	var finalMethods []string
	var finalContracts []string
	var finalOwnedContracts []string
	var finalContractFunctions map[string][]string
	var finalClaims []Claim
	var finalRateLimitRPS *int
	var finalRateLimitDaily *int
	firstMembership := true

	for _, m := range memberships {
		// Get the group hierarchy for this membership
		hierarchy, err := r.store.GetGroupHierarchy(ctx, m.Group.ID)
		if err != nil {
			return nil, err
		}

		// Compute permissions for this membership using restrictive inheritance
		membershipPerms, err := r.computeMembershipPermissions(ctx, hierarchy)
		if err != nil {
			return nil, err
		}

		// Collect claims from the role
		if m.Role != nil {
			for _, claim := range m.Role.Claims {
				if !slices.Contains(finalClaims, claim) {
					finalClaims = append(finalClaims, claim)
				}
			}
		}

		if firstMembership {
			// First membership - use its permissions as baseline
			finalMethods = membershipPerms.AllowMethods
			finalContracts = membershipPerms.AllowContracts
			finalOwnedContracts = membershipPerms.OwnedContracts
			finalContractFunctions = membershipPerms.ContractFunctions
			finalRateLimitRPS = membershipPerms.RateLimitRPS
			finalRateLimitDaily = membershipPerms.RateLimitDaily
			firstMembership = false
		} else {
			// Subsequent memberships - UNION the permissions
			finalMethods = unionStrings(finalMethods, membershipPerms.AllowMethods)
			finalContracts = unionStrings(finalContracts, membershipPerms.AllowContracts)
			finalOwnedContracts = unionStrings(finalOwnedContracts, membershipPerms.OwnedContracts)
			finalContractFunctions = unionContractFunctions(finalContractFunctions, membershipPerms.ContractFunctions)

			// For rate limits across memberships, take the MAXIMUM (most permissive)
			// because user should benefit from their best membership
			finalRateLimitRPS = maxIntPtr(finalRateLimitRPS, membershipPerms.RateLimitRPS)
			finalRateLimitDaily = maxIntPtr(finalRateLimitDaily, membershipPerms.RateLimitDaily)
		}
	}

	return &EffectivePermissions{
		ID:                uuid.New().String(),
		UserID:            userID,
		OrgID:             orgID,
		AllowMethods:      finalMethods,
		AllowContracts:    finalContracts,
		OwnedContracts:    finalOwnedContracts,
		ContractFunctions: finalContractFunctions,
		Claims:            finalClaims,
		RateLimitRPS:      finalRateLimitRPS,
		RateLimitDaily:    finalRateLimitDaily,
		ComputedAt:        time.Now(),
		ExpiresAt:         time.Now().Add(r.cacheTTL),
	}, nil
}

// computeMembershipPermissions computes permissions for a single membership
// by traversing the group hierarchy with restrictive inheritance.
func (r *Resolver) computeMembershipPermissions(ctx context.Context, hierarchy []*Group) (*GroupPermissions, error) {
	if len(hierarchy) == 0 {
		return &GroupPermissions{
			AllowMethods:      []string{},
			AllowContracts:    []string{},
			OwnedContracts:    []string{},
			ContractFunctions: make(map[string][]string),
		}, nil
	}

	// Start with the root group's permissions
	result := &GroupPermissions{
		AllowMethods:      nil, // nil means "all allowed" until we see the first actual permissions
		AllowContracts:    nil,
		OwnedContracts:    []string{},
		ContractFunctions: make(map[string][]string),
	}

	for _, group := range hierarchy {
		perms, err := r.store.GetGroupPermissions(ctx, group.ID)
		if err != nil {
			return nil, err
		}
		if perms == nil {
			continue // Group has no permissions defined, skip
		}

		// Apply INTERSECTION for methods (restrictive)
		if result.AllowMethods == nil {
			// First permissions encountered
			result.AllowMethods = perms.AllowMethods
		} else if len(perms.AllowMethods) > 0 {
			result.AllowMethods = intersectStrings(result.AllowMethods, perms.AllowMethods)
		}

		// Apply INTERSECTION for contracts (restrictive)
		if result.AllowContracts == nil {
			result.AllowContracts = perms.AllowContracts
		} else if len(perms.AllowContracts) > 0 {
			result.AllowContracts = intersectStrings(result.AllowContracts, perms.AllowContracts)
		}

		// Apply UNION for owned contracts (ownership propagates down)
		result.OwnedContracts = unionStrings(result.OwnedContracts, perms.OwnedContracts)

		// Apply INTERSECTION for contract functions (restrictive per contract)
		// If child specifies functions for a contract, they narrow the parent's
		result.ContractFunctions = intersectContractFunctions(result.ContractFunctions, perms.ContractFunctions)

		// Apply MINIMUM for rate limits (most restrictive wins)
		result.RateLimitRPS = minIntPtr(result.RateLimitRPS, perms.RateLimitRPS)
		result.RateLimitDaily = minIntPtr(result.RateLimitDaily, perms.RateLimitDaily)
	}

	// Ensure we return empty slices instead of nil
	if result.AllowMethods == nil {
		result.AllowMethods = []string{}
	}
	if result.AllowContracts == nil {
		result.AllowContracts = []string{}
	}

	return result, nil
}

// InvalidateUserPermissions invalidates the cache for a specific user.
func (r *Resolver) InvalidateUserPermissions(ctx context.Context, userID string) error {
	return r.store.InvalidateCacheForUser(ctx, userID)
}

// InvalidateOrgPermissions invalidates the cache for all users in an organization.
func (r *Resolver) InvalidateOrgPermissions(ctx context.Context, orgID string) error {
	return r.store.InvalidateCacheForOrg(ctx, orgID)
}

// InvalidateGroupPermissions invalidates the cache for all users in a group.
func (r *Resolver) InvalidateGroupPermissions(ctx context.Context, groupID string) error {
	return r.store.InvalidateCacheForGroup(ctx, groupID)
}

// Helper functions

// intersectStrings returns the intersection of two string slices.
func intersectStrings(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return []string{}
	}

	set := make(map[string]bool)
	for _, s := range a {
		set[strings.ToLower(s)] = true
	}

	var result []string
	for _, s := range b {
		if set[strings.ToLower(s)] {
			result = append(result, s)
		}
	}

	return result
}

// unionStrings returns the union of two string slices (case-insensitive dedup).
func unionStrings(a, b []string) []string {
	set := make(map[string]string) // lowercase -> original
	for _, s := range a {
		set[strings.ToLower(s)] = s
	}
	for _, s := range b {
		key := strings.ToLower(s)
		if _, exists := set[key]; !exists {
			set[key] = s
		}
	}

	result := make([]string, 0, len(set))
	for _, v := range set {
		result = append(result, v)
	}
	return result
}

// minIntPtr returns the minimum of two *int values, treating nil as "unlimited".
func minIntPtr(a, b *int) *int {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a < *b {
		return a
	}
	return b
}

// maxIntPtr returns the maximum of two *int values, treating nil as "unlimited".
func maxIntPtr(a, b *int) *int {
	if a == nil || b == nil {
		return nil // Either is unlimited, so result is unlimited
	}
	if *a > *b {
		return a
	}
	return b
}

// intersectContractFunctions applies INTERSECTION logic for contract function restrictions.
// If both maps have the same contract, the result is the intersection of their selectors.
// If only one map has a contract, that contract's selectors are used (restrictive).
func intersectContractFunctions(a, b map[string][]string) map[string][]string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}

	result := make(map[string][]string)

	// Include all contracts from both maps
	allContracts := make(map[string]bool)
	for c := range a {
		allContracts[strings.ToLower(c)] = true
	}
	for c := range b {
		allContracts[strings.ToLower(c)] = true
	}

	for contract := range allContracts {
		aSelectors, aHas := a[contract]
		bSelectors, bHas := b[contract]

		if aHas && bHas {
			// Both have the contract - intersect the selectors
			result[contract] = intersectStrings(aSelectors, bSelectors)
		} else if aHas {
			// Only a has the contract - use a's restrictions
			result[contract] = aSelectors
		} else {
			// Only b has the contract - use b's restrictions
			result[contract] = bSelectors
		}
	}

	return result
}

// unionContractFunctions applies UNION logic for contract function permissions.
// Used when merging permissions across multiple memberships - user gets all allowed functions.
func unionContractFunctions(a, b map[string][]string) map[string][]string {
	if len(a) == 0 && len(b) == 0 {
		return make(map[string][]string)
	}
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}

	result := make(map[string][]string)

	// Copy all from a
	for contract, selectors := range a {
		result[strings.ToLower(contract)] = append([]string{}, selectors...)
	}

	// Merge in all from b
	for contract, selectors := range b {
		lc := strings.ToLower(contract)
		if existing, has := result[lc]; has {
			// Union the selectors for this contract
			result[lc] = unionStrings(existing, selectors)
		} else {
			result[lc] = append([]string{}, selectors...)
		}
	}

	return result
}
