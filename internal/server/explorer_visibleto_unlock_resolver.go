package server

import (
	"context"
	"strings"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// dbVisibleToUnlockResolver implements explorer.VisibleToUnlockResolver
// by checking each contract's `allow_visibleto_unlock` flag against the
// shared rbac.IsViewerEligibleForVisibleToUnlock gate. Both must be
// true for the contract to appear in the result map.
//
// Mirrors the JSON-RPC layer's processor_event_rules.go::
// buildVisibleToUnlockableMap so the two layers agree on the
// (viewer, contract) → unlock triple — required by the access /
// visibility symmetry invariant in REDACTION_SPEC.md.
//
// Per-call de-duplication and short-circuiting on the flag check
// avoids invoking GetEffectivePermissionsByIDs for contracts whose
// owners haven't opted in.
type dbVisibleToUnlockResolver struct {
	access *rbac.AccessController
}

func newDBVisibleToUnlockResolver(access *rbac.AccessController) *dbVisibleToUnlockResolver {
	return &dbVisibleToUnlockResolver{access: access}
}

// Resolve returns the subset of the supplied addresses that are
// (a) registered with `allow_visibleto_unlock = true` AND (b) the
// viewer is unlock-eligible for. See explorer.VisibleToUnlockResolver
// for the full contract.
func (r *dbVisibleToUnlockResolver) Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool {
	out := make(map[string]bool)
	if r.access == nil || viewerDID == "" || len(addresses) == 0 {
		return out
	}
	store := r.access.Store()
	if store == nil {
		return out
	}

	seen := make(map[string]struct{}, len(addresses))
	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		addrLower := strings.ToLower(addr)
		if _, dup := seen[addrLower]; dup {
			continue
		}
		seen[addrLower] = struct{}{}

		contract, err := store.GetContractByAddressGlobal(ctx, addrLower)
		if err != nil || contract == nil || !contract.AllowVisibleToUnlock {
			continue
		}
		if rbac.IsViewerEligibleForVisibleToUnlock(ctx, r.access, viewerDID, addrLower) {
			out[addrLower] = true
		}
	}
	return out
}

// Compile-time assertion that *dbVisibleToUnlockResolver satisfies
// explorer.VisibleToUnlockResolver.
var _ explorer.VisibleToUnlockResolver = (*dbVisibleToUnlockResolver)(nil)
