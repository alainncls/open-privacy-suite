package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"privacy-proxy/internal/evm/precompile"
	"privacy-proxy/internal/tracer"
)

// TraceValidatorStore is a subset of Store used by TraceValidator.
// This allows using either the full Store or a mock implementation.
type TraceValidatorStore interface {
	// Contract ownership methods
	IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error)
	GetContractOwnerOrgID(ctx context.Context, address string) (string, error)

	// Shared infrastructure methods
	IsSharedInfrastructure(ctx context.Context, address string) (bool, error)
	CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error
	ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error)
	DeleteSharedInfrastructure(ctx context.Context, address string) error
}

// TraceValidator validates transaction traces against RBAC rules.
// It ensures that all addresses touched by a transaction are allowed
// for the user's organization(s), enforcing cross-org isolation.
type TraceValidator struct {
	store          TraceValidatorStore
	precompileFunc func(addr string) bool // For dependency injection in tests
}

// TraceValidationResult contains the result of trace validation.
type TraceValidationResult struct {
	Allowed      bool   // Whether the transaction trace is allowed
	Reason       string // Reason for denial (if any)
	DeniedTarget string // Address that caused denial (if any)
}

// SharedInfrastructure represents a globally accessible contract (e.g., Uniswap router).
// These contracts are allowed for all organizations and do not require org ownership.
type SharedInfrastructure struct {
	Address     string    `json:"address"`     // lowercase 0x-prefixed address
	Name        string    `json:"name"`        // Human-readable name (e.g., "Uniswap V3 Router")
	Description string    `json:"description"` // Description of the contract
	CreatedAt   time.Time `json:"created_at"`
}

// NewTraceValidator creates a new trace validator.
func NewTraceValidator(store TraceValidatorStore) *TraceValidator {
	return &TraceValidator{
		store:          store,
		precompileFunc: precompile.IsPrecompileAddress,
	}
}

// ValidateTrace checks if all addresses in a transaction trace are allowed
// for the user's organizations.
//
// The validation follows this order:
// 1. If trace has CREATE or CREATE2, deny (runtime contract creation not permitted)
// 2. For each CallTarget:
//    a. Filter precompiles (0x01-0x09): always allow
//    b. Check if target is shared infrastructure: always allow
//    c. Check if target is owned by any of user's orgs: allow if member
//    d. If not owned by user's org, check if owned by another org: DENY
//    e. If public (not owned by any org): allow
func (v *TraceValidator) ValidateTrace(
	ctx context.Context,
	userOrgIDs map[string]bool,
	trace *tracer.TraceResult,
) (*TraceValidationResult, error) {
	if trace == nil {
		return &TraceValidationResult{
			Allowed: true,
			Reason:  "",
		}, nil
	}

	// Rule 1: Block runtime CREATE/CREATE2 operations
	if trace.HasCreate || trace.HasCreate2 {
		return &TraceValidationResult{
			Allowed: false,
			Reason:  "runtime CREATE/CREATE2 not permitted",
		}, nil
	}

	// Rule 2: Validate each call target
	for _, target := range trace.CallTargets {
		// Skip CREATE/CREATE2 targets (already handled above, but be defensive)
		if target.Type == "CREATE" || target.Type == "CREATE2" {
			continue
		}

		// Normalize the target address
		addr := normalizeTraceAddr(target.To)

		// Skip empty addresses
		if addr == "" || addr == "0x" || addr == "0x0000000000000000000000000000000000000000" {
			continue
		}

		// Rule 2a: Precompiles are always allowed
		if v.precompileFunc(addr) {
			continue
		}

		// Rule 2b: Check if target is shared infrastructure (always allowed)
		isShared, err := v.store.IsSharedInfrastructure(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to check shared infrastructure: %w", err)
		}
		if isShared {
			continue
		}

		// Rule 2c: Check if target is owned by any of the user's orgs
		isOwnedByUserOrg := false
		for orgID := range userOrgIDs {
			owned, err := v.store.IsAddressOwnedByOrg(ctx, addr, orgID)
			if err != nil {
				return nil, fmt.Errorf("failed to check address ownership for org %s: %w", orgID, err)
			}
			if owned {
				isOwnedByUserOrg = true
				break
			}
		}
		if isOwnedByUserOrg {
			continue
		}

		// Rule 2d: Check if owned by another org (not the user's) -> DENY
		ownerOrgID, err := v.store.GetContractOwnerOrgID(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to get contract owner: %w", err)
		}
		if ownerOrgID != "" {
			// The contract is owned by another organization
			return &TraceValidationResult{
				Allowed:      false,
				Reason:       fmt.Sprintf("address %s is owned by another organization", addr),
				DeniedTarget: addr,
			}, nil
		}

		// Rule 2e: Public address (not owned by any org) -> allow
		// This is the implicit case - we continue to the next target
	}

	return &TraceValidationResult{
		Allowed: true,
	}, nil
}

// normalizeTraceAddr normalizes an address to lowercase with 0x prefix.
// This has a unique name to avoid conflicts with other normalize functions in the package.
func normalizeTraceAddr(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	if addr == "" {
		return ""
	}
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	return addr
}
