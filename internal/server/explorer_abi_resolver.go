package server

import (
	"context"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// dbABIResolver implements explorer.ABIResolver by consulting the RBAC
// store (the same store the JSON-RPC layer's storeABIProvider uses) and
// applying the unified rbac.ResolveContractABI logic — custom ABI first,
// built-in registry fallback (ERC-20 / ERC-721 from metadata.token_type).
//
// Wiring this into RedactionEngine at server startup closes the
// pre-RD-889 explorer-side gap where the redactor consulted only the
// explorer's local ContractStore (no metadata field, no built-in
// fallback). After this resolver is wired, both layers consult one
// source of truth — required by the access/visibility symmetry
// invariant in REDACTION_SPEC.md.
//
// Per-request caching is deliberately omitted here because the
// RedactionEngine already caches resolved ABIs in its Phase 3 map for
// the duration of a single RedactLogs call. If we ever reuse this
// resolver from a longer-lived context we should add a TTL cache, but
// the current call sites are short-lived per HTTP request.
type dbABIResolver struct {
	store rbac.Store
}

func newDBABIResolver(store rbac.Store) *dbABIResolver {
	return &dbABIResolver{store: store}
}

// Resolve returns the resolved ABI JSON for the given contract address,
// or "" when no ABI is resolvable. See explorer.ABIResolver for the
// contract.
//
// Resolution order (mirrors the JSON-RPC layer's storeABIProvider in
// internal/server/event_log_filter.go and the helper RD-875 will merge
// as rbac.ResolveContractABI):
//  1. Custom ABI uploaded for the contract → return it.
//  2. metadata.token_type matches the built-in registry (ERC-20 /
//     ERC-721) → return the built-in ABI.
//  3. Otherwise → return "" (callers treat as "no resolvable ABI").
//
// When RD-875 merges, this body collapses to a single call to
// rbac.ResolveContractABI(contract). Inline for now so RD-889 doesn't
// gate on the ordering of merges.
func (r *dbABIResolver) Resolve(ctx context.Context, address string) string {
	if r.store == nil {
		return ""
	}
	contract, err := r.store.GetContractByAddressGlobal(ctx, address)
	if err != nil || contract == nil {
		return ""
	}
	if contract.ABI != "" {
		return contract.ABI
	}
	if contract.Metadata != nil {
		if tokenType, ok := contract.Metadata["token_type"].(string); ok {
			return rbac.GetBuiltInABI(tokenType)
		}
	}
	return ""
}

// Compile-time assertion that *dbABIResolver satisfies explorer.ABIResolver.
var _ explorer.ABIResolver = (*dbABIResolver)(nil)
