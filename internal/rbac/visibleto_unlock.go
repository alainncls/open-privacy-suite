package rbac

import (
	"context"
	"strings"
)

// IsViewerEligibleForVisibleToUnlock implements the eligibility gate for
// the RD-874 per-contract visibleTo unlock semantic.
//
// Returns true if and only if:
//
//  1. viewerDID resolves to a real user record (anonymous viewers — no
//     `users` row — are denied here, mirroring the spec's "anonymous /
//     default-group access excluded" rule).
//  2. The contract is registered (the address has an owning org).
//  3. The viewer holds a `contract_grant` on this specific contract via
//     at least one of their group memberships in the contract's owning
//     org. This is the "group added to the contract without event-level
//     rights" gate from the CTO call notes — having a grant is enough,
//     even if the grant's event_rules say deny-all.
//
// Returning true does NOT by itself grant the unlock. The two other
// preconditions — `contract.AllowVisibleToUnlock` AND viewer listed in
// the tx's `visibleTo` set — must also hold. Callers are expected to
// pre-compute this map per request and pass it down to the filter
// layers so the per-log check stays O(1).
//
// Cross-org isolation: `GetEffectivePermissionsByIDs` only resolves
// grants in the supplied owning-org. Even if the viewer has unrelated
// access in another org, a contract whose owning org the viewer has no
// grant in returns false here. The check therefore re-uses the same
// org-scoping defence that `dbAdminContractsResolver` and
// `dbEventRuleChecker` apply.
func IsViewerEligibleForVisibleToUnlock(ctx context.Context, access *AccessController, viewerDID, contractAddress string) bool {
	if access == nil || viewerDID == "" || contractAddress == "" {
		return false
	}
	addr := strings.ToLower(contractAddress)

	user, err := access.Store().GetUserByExternalID(ctx, viewerDID)
	if err != nil || user == nil {
		return false
	}

	ownerOrgID, err := access.Store().GetContractOwnerOrgID(ctx, addr)
	if err != nil || ownerOrgID == "" {
		return false
	}

	perms, err := access.GetEffectivePermissionsByIDs(ctx, user.ID, ownerOrgID)
	if err != nil || perms == nil {
		return false
	}
	return perms.HasContractAccess(addr)
}
