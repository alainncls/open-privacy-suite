package rbac

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Resolver computes effective permissions for users.
type Resolver struct {
	store    Store
	cacheTTL time.Duration

	// inFlight tracks computations that are in progress to prevent cache stampede
	inFlight   map[string]*inFlightEntry
	inFlightMu sync.RWMutex
}

// inFlightEntry holds the result of an in-progress permission computation.
// Uses a closed channel as a broadcast signal so all waiting goroutines are woken.
type inFlightEntry struct {
	done  chan struct{} // closed when computation is complete
	perms *EffectivePermissions
	err   error
}

// NewResolver creates a new permission resolver.
func NewResolver(store Store, cacheTTL time.Duration) *Resolver {
	return &Resolver{
		store:    store,
		cacheTTL: cacheTTL,
		inFlight: make(map[string]*inFlightEntry),
	}
}

// ResolvePermissions computes the effective permissions for a user in an organization.
// It first checks the cache, then computes permissions if not cached.
// Uses single-flight pattern to prevent cache stampede when multiple requests
// come in simultaneously for the same user+org combination.
func (r *Resolver) ResolvePermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	cacheKey := userID + ":" + orgID

	// Check in-memory cache first (fast path)
	cached, err := r.store.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if cached != nil {
		return cached, nil
	}

	// Check if another goroutine is already computing this permission
	r.inFlightMu.RLock()
	entry, exists := r.inFlight[cacheKey]
	r.inFlightMu.RUnlock()

	if exists {
		// Wait for the in-progress computation
		select {
		case <-entry.done:
			return entry.perms, entry.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// No computation in progress, start one
	entry = &inFlightEntry{
		done: make(chan struct{}),
	}

	r.inFlightMu.Lock()
	// Double-check after acquiring write lock
	if existing, exists := r.inFlight[cacheKey]; exists {
		// Another goroutine beat us, wait on their computation
		r.inFlightMu.Unlock()
		select {
		case <-existing.done:
			return existing.perms, existing.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r.inFlight[cacheKey] = entry
	r.inFlightMu.Unlock()

	// Compute permissions
	perms, err := r.computePermissions(ctx, userID, orgID)

	// Store result and broadcast to all waiting goroutines
	entry.perms = perms
	entry.err = err
	close(entry.done)

	// Clean up in-flight entry
	r.inFlightMu.Lock()
	delete(r.inFlight, cacheKey)
	r.inFlightMu.Unlock()

	if err != nil {
		return nil, err
	}

	// Cache the result (fire and forget - errors are logged but not critical)
	go func() {
		if err := r.store.SetCachedPermissions(ctx, perms); err != nil {
			// Log error but don't fail
		}
	}()

	return perms, nil
}

// computePermissions calculates effective permissions using the contract-centric RBAC model.
//
// Algorithm:
//  1. Get user's memberships in the org
//  2. Check for org admin memberships - if found, grant all claims on all contracts
//  3. For each membership:
//     a. Get the group hierarchy (root -> ... -> current)
//     b. Compute permissions through hierarchy with INTERSECTION (child narrows parent)
//     c. Collect contract grants and group access along the hierarchy
//  4. Merge permissions across multiple group memberships (UNION - user benefits from all groups)
//  5. Rate limits: MINIMUM within hierarchy, MAXIMUM across memberships
func (r *Resolver) computePermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	// Get user's memberships in this org with details
	memberships, err := r.store.ListUserMembershipsInOrg(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	if len(memberships) == 0 {
		// User has no memberships - return empty permissions
		return &EffectivePermissions{
			ID:             uuid.New().String(),
			UserID:         userID,
			OrgID:          orgID,
			AllowedMethods: []string{},
			ContractAccess: make(map[string]ContractAccess),
			Claims:  []Claim{},
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(r.cacheTTL),
		}, nil
	}

	// Check if user is member of any org admin group
	isOrgAdmin := false
	for _, m := range memberships {
		if m.Group.IsOrgAdmin {
			isOrgAdmin = true
			break
		}
	}

	// If user is org admin, grant all claims on all contracts
	if isOrgAdmin {
		return r.computeOrgAdminPermissions(ctx, userID, orgID, memberships)
	}

	// Track final merged permissions across all memberships
	var finalMethods []string
	finalContractAccess := make(map[string]ContractAccess)
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

		// Compute permissions through the hierarchy with restrictive inheritance
		membershipPerms, err := r.computeHierarchyPermissions(ctx, hierarchy)
		if err != nil {
			return nil, err
		}

		if firstMembership {
			// First membership - use its permissions as baseline
			finalMethods = membershipPerms.AllowedMethods
			finalContractAccess = membershipPerms.ContractAccess
			finalClaims = membershipPerms.Claims
			finalRateLimitRPS = membershipPerms.RateLimitRPS
			finalRateLimitDaily = membershipPerms.RateLimitDaily
			firstMembership = false
		} else {
			// Subsequent memberships - UNION the permissions (user benefits from all groups)
			finalMethods = unionStrings(finalMethods, membershipPerms.AllowedMethods)
			finalContractAccess = unionContractAccess(finalContractAccess, membershipPerms.ContractAccess)
			finalClaims = unionClaims(finalClaims, membershipPerms.Claims)

			// For rate limits across memberships, take the MAXIMUM (most permissive)
			finalRateLimitRPS = maxIntPtr(finalRateLimitRPS, membershipPerms.RateLimitRPS)
			finalRateLimitDaily = maxIntPtr(finalRateLimitDaily, membershipPerms.RateLimitDaily)
		}
	}

	return &EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: finalMethods,
		ContractAccess: finalContractAccess,
		Claims:         ExpandClaims(finalClaims), // expand so admin→deploy etc. are included
		RateLimitRPS:   finalRateLimitRPS,
		RateLimitDaily: finalRateLimitDaily,
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(r.cacheTTL),
	}, nil
}

// computeOrgAdminPermissions computes permissions for org admin users.
// Org admins get all claims on all contracts in the organization.
func (r *Resolver) computeOrgAdminPermissions(ctx context.Context, userID, orgID string, memberships []*MembershipWithDetails) (*EffectivePermissions, error) {
	// Get all contracts in the organization
	contracts, err := r.store.ListContracts(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Build contract access with all claims for each contract
	allClaims := AllClaims()
	contractAccess := make(map[string]ContractAccess)
	for _, contract := range contracts {
		contractAccess[strings.ToLower(contract.Address)] = ContractAccess{
			Claims:    allClaims,
			Functions: nil, // all functions
		}
	}

	// Still compute rate limits from memberships (take the most permissive)
	var finalRateLimitRPS *int
	var finalRateLimitDaily *int
	var finalMethods []string

	for _, m := range memberships {
		// Get the group hierarchy for this membership to get rate limits
		hierarchy, err := r.store.GetGroupHierarchy(ctx, m.Group.ID)
		if err != nil {
			return nil, err
		}

		membershipPerms, err := r.computeHierarchyPermissions(ctx, hierarchy)
		if err != nil {
			return nil, err
		}

		finalMethods = unionStrings(finalMethods, membershipPerms.AllowedMethods)
		finalRateLimitRPS = maxIntPtr(finalRateLimitRPS, membershipPerms.RateLimitRPS)
		finalRateLimitDaily = maxIntPtr(finalRateLimitDaily, membershipPerms.RateLimitDaily)
	}

	return &EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: finalMethods,
		ContractAccess: contractAccess,
		Claims:  allClaims, // Org admins get all default claims too
		RateLimitRPS:   finalRateLimitRPS,
		RateLimitDaily: finalRateLimitDaily,
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(r.cacheTTL),
	}, nil
}

// hierarchyPerms holds permissions computed through a group hierarchy.
type hierarchyPerms struct {
	AllowedMethods []string
	ContractAccess map[string]ContractAccess // address -> access
	Claims  []Claim
	RateLimitRPS   *int
	RateLimitDaily *int
}

// computeHierarchyPermissions computes permissions by traversing the group hierarchy
// from root to leaf, applying INTERSECTION at each level (child narrows parent).
func (r *Resolver) computeHierarchyPermissions(ctx context.Context, hierarchy []*Group) (*hierarchyPerms, error) {
	if len(hierarchy) == 0 {
		return &hierarchyPerms{
			AllowedMethods: []string{},
			ContractAccess: make(map[string]ContractAccess),
			Claims:  []Claim{},
		}, nil
	}

	// Start with no restrictions (nil means "all allowed" until we see the first actual permissions)
	result := &hierarchyPerms{
		AllowedMethods: nil,
		ContractAccess: nil, // nil means "all allowed" until first group has grants
		Claims:  nil,
	}

	// Track contract data for batch loading
	contractAddresses := make(map[string]string)     // contractID -> address
	groupGrants := make(map[string][]*ContractGrant) // groupID -> grants
	var contractIDs []string                         // IDs to batch load

	for _, group := range hierarchy {
		// Get group access settings
		access, err := r.store.GetGroupAccess(ctx, group.ID)
		if err != nil {
			return nil, err
		}

		if access != nil {
			// Apply INTERSECTION for allowed methods (restrictive inheritance).
			// nil means "not set / inherit from parent" (no narrowing).
			// []string{} means "explicitly empty / deny all" (narrows to empty).
			if result.AllowedMethods == nil {
				result.AllowedMethods = access.AllowedMethods
			} else if access.AllowedMethods != nil {
				result.AllowedMethods = intersectStrings(result.AllowedMethods, access.AllowedMethods)
			}

			// Apply INTERSECTION for default claims.
			// nil means "not set / inherit from parent" (no narrowing).
			// []Claim{} means "explicitly empty / deny all" (narrows to empty).
			if result.Claims == nil {
				result.Claims = access.Claims
			} else if access.Claims != nil {
				result.Claims = IntersectClaims(result.Claims, access.Claims)
			}

			// Apply MINIMUM for rate limits (most restrictive wins within hierarchy)
			result.RateLimitRPS = minIntPtr(result.RateLimitRPS, access.RateLimitRPS)
			result.RateLimitDaily = minIntPtr(result.RateLimitDaily, access.RateLimitDaily)
		}

		// Get contract grants for this group
		grants, err := r.store.ListContractGrantsByGroup(ctx, group.ID)
		if err != nil {
			return nil, err
		}
		groupGrants[group.ID] = grants

		// Collect contract IDs we need to load
		for _, grant := range grants {
			if _, ok := contractAddresses[grant.ContractID]; !ok {
				contractIDs = append(contractIDs, grant.ContractID)
			}
		}
	}

	// Batch load all contracts we need
	if len(contractIDs) > 0 {
		contracts, err := r.store.GetContractsByIDs(ctx, contractIDs)
		if err != nil {
			return nil, err
		}
		for id, contract := range contracts {
			contractAddresses[id] = strings.ToLower(contract.Address)
		}
	}

	// Now process grants using pre-loaded contract addresses
	// Claims come from the GROUP (via GroupAccess), not from the grant itself.
	// The grant just establishes that the group has access to the contract,
	// with optional function restrictions from the grant.
	for _, group := range hierarchy {
		// Get the group's claims from its access settings
		access, err := r.store.GetGroupAccess(ctx, group.ID)
		if err != nil {
			return nil, err
		}

		// Get the claims to use for this group's grants
		// If group has no access settings, use empty claims
		var groupClaims []Claim
		if access != nil {
			groupClaims = access.Claims
		}

		grants := groupGrants[group.ID]
		for _, grant := range grants {
			address, ok := contractAddresses[grant.ContractID]
			if !ok {
				continue // Contract deleted, skip
			}

			// Initialize result.ContractAccess if this is the first grant we've seen
			if result.ContractAccess == nil {
				result.ContractAccess = make(map[string]ContractAccess)
			}

			// Apply contract grant with INTERSECTION logic
			// Claims come from the group, functions come from the grant
			if existing, ok := result.ContractAccess[address]; ok {
				// Child narrows parent - intersect claims and functions
				// Claims are intersected with group's claims (inherited from GroupAccess)
				result.ContractAccess[address] = ContractAccess{
					Claims:    IntersectClaims(existing.Claims, groupClaims),
					Functions: intersectFunctions(existing.Functions, grant.Functions),
				}
			} else {
				// First time seeing this contract in hierarchy - use group's claims
				result.ContractAccess[address] = ContractAccess{
					Claims:    groupClaims,
					Functions: grant.Functions,
				}
			}
		}
	}

	// Ensure we return empty values instead of nil
	if result.AllowedMethods == nil {
		result.AllowedMethods = []string{}
	}
	if result.ContractAccess == nil {
		result.ContractAccess = make(map[string]ContractAccess)
	}
	if result.Claims == nil {
		result.Claims = []Claim{}
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

// intersectStrings returns the intersection of two string slices (case-insensitive).
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

// IntersectClaims returns the intersection of two claim slices.
// Used both by the resolver (hierarchy computation) and by admin handlers
// (computing effective claims for display).
func IntersectClaims(a, b []Claim) []Claim {
	if len(a) == 0 || len(b) == 0 {
		return []Claim{}
	}

	set := make(map[Claim]bool)
	for _, c := range a {
		set[c] = true
	}

	var result []Claim
	for _, c := range b {
		if set[c] {
			result = append(result, c)
		}
	}

	return result
}

// unionClaims returns the union of two claim slices.
func unionClaims(a, b []Claim) []Claim {
	set := make(map[Claim]bool)
	for _, c := range a {
		set[c] = true
	}
	for _, c := range b {
		set[c] = true
	}

	result := make([]Claim, 0, len(set))
	for c := range set {
		result = append(result, c)
	}
	return result
}

// intersectFunctions returns the intersection of two FunctionRule slices by selector.
// If either is nil, it means "all functions allowed" - return the other.
// If both are nil, return nil (all allowed).
// If both have values, return rules whose selectors appear in both (keeping the
// stricter param_rules from whichever side has them).
func intersectFunctions(a, b []FunctionRule) []FunctionRule {
	// nil means "all functions allowed"
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}

	// Non-nil but empty = "no functions allowed" — intersection with anything is empty
	if len(a) == 0 || len(b) == 0 {
		return []FunctionRule{}
	}

	// Index b by selector for O(n) lookup
	bMap := make(map[string]FunctionRule, len(b))
	for _, rule := range b {
		bMap[strings.ToLower(rule.Selector)] = rule
	}

	result := []FunctionRule{}
	for _, ruleA := range a {
		if ruleB, ok := bMap[strings.ToLower(ruleA.Selector)]; ok {
			// Both sides allow this selector - keep the one with param rules
			// (stricter). If both have param rules, keep b's (child narrows parent).
			merged := ruleA
			if len(ruleB.ParamRules) > 0 {
				merged.ParamRules = ruleB.ParamRules
			}
			result = append(result, merged)
		}
	}
	return result
}

// unionFunctions returns the union of two FunctionRule slices by selector.
// If either is nil, it means "all functions allowed" - return nil.
// If both have values, return the union (user gets all allowed functions).
func unionFunctions(a, b []FunctionRule) []FunctionRule {
	// nil means "all functions allowed" - if either is unrestricted, result is unrestricted
	if a == nil || b == nil {
		return nil
	}

	// Both have restrictions - union them (user gets all allowed functions)
	seen := make(map[string]FunctionRule, len(a))
	for _, rule := range a {
		seen[strings.ToLower(rule.Selector)] = rule
	}
	for _, rule := range b {
		key := strings.ToLower(rule.Selector)
		if existing, ok := seen[key]; ok {
			// Both sides allow this selector. If either side has no param rules,
			// the union is the less restrictive one (no param rules).
			if len(existing.ParamRules) == 0 || len(rule.ParamRules) == 0 {
				seen[key] = FunctionRule{Selector: rule.Selector}
			}
			// else: both have param rules, keep existing (arbitrary but consistent)
		} else {
			seen[key] = rule
		}
	}

	result := make([]FunctionRule, 0, len(seen))
	for _, rule := range seen {
		result = append(result, rule)
	}
	return result
}

// unionContractAccess merges two ContractAccess maps, taking the UNION of claims and functions.
// Used when merging permissions across multiple memberships - user benefits from all groups.
func unionContractAccess(a, b map[string]ContractAccess) map[string]ContractAccess {
	if len(a) == 0 && len(b) == 0 {
		return make(map[string]ContractAccess)
	}
	if len(a) == 0 {
		// Return a copy of b
		result := make(map[string]ContractAccess, len(b))
		for k, v := range b {
			result[k] = v
		}
		return result
	}
	if len(b) == 0 {
		// Return a copy of a
		result := make(map[string]ContractAccess, len(a))
		for k, v := range a {
			result[k] = v
		}
		return result
	}

	result := make(map[string]ContractAccess)

	// Copy all from a
	for addr, access := range a {
		result[strings.ToLower(addr)] = access
	}

	// Merge in all from b
	for addr, access := range b {
		lc := strings.ToLower(addr)
		if existing, has := result[lc]; has {
			// Union the claims and functions for this contract
			result[lc] = ContractAccess{
				Claims:    unionClaims(existing.Claims, access.Claims),
				Functions: unionFunctions(existing.Functions, access.Functions),
			}
		} else {
			result[lc] = access
		}
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

// HasClaim is a helper to check if a claim exists in a slice.
func HasClaim(claims []Claim, claim Claim) bool {
	return slices.Contains(claims, claim)
}
