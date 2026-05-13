package rbac

import (
	"context"

	"privacy-proxy/internal/evm/bytecode"
)

// DeploymentValidator extracts metadata from contract-deployment bytecode.
//
// SCOPE (post-M10, security audit follow-up to RD-915):
//
// This validator used to perform two separate jobs:
//
//   1. Extract metadata from the bytecode (HasCreate/HasCreate2 flags,
//      proxy-pattern detection — needed by the proxy auto-registration
//      flow and by the admin UI to label proxies).
//
//   2. Statically validate constant CALL/DELEGATECALL targets and
//      constructor-argument addresses against the org's allowed set.
//
// Job #2 was a security gate, but it only caught CONSTANT targets;
// dynamic targets (constructor args, storage reads, computed addresses)
// slipped through silently. A code comment claimed runtime tracing
// covered the dynamic cases, but no runtime tracing was wired for the
// deploy path. The combination meant a deployer with the deploy claim
// could ship a constructor that took `address foreignContract` as a
// constructor arg and STATICCALL'd into another org's private contract
// during construction, persisting the foreign state in the new
// contract's initial storage.
//
// M10 closed that by routing deploys through runtime tracing
// (debug_traceCall against empty `to`), which validates EVERY executed
// frame regardless of how the target address was computed. Once that
// gate exists in the JSON-RPC processor (validateDeployWithTracing),
// the static call-target / constructor-arg analysis here is
// strictly subsumed by it — and worse, leaving it in place duplicates
// the trace's effort for the constant case while reinforcing the false
// impression that bytecode analysis defends against dynamic targets.
//
// What's left here is JOB #1 ONLY: bytecode metadata extraction
// (HasCreate, HasCreate2, IsProxy, ProxyType) for the downstream
// proxy auto-registration flow. Operators who run upstream nodes
// without `debug_*` exposed lose the M10 gate; they should either
// re-enable debug_* on their RPC service or accept the deploy-time
// cross-org leak risk. The architectural assumption (we run our own
// geth/erigon nodes with debug_* available) makes this the right
// trade-off.
type DeploymentValidator struct {
	store Store
}

// NewDeploymentValidator creates a new deployment validator.
func NewDeploymentValidator(store Store) *DeploymentValidator {
	return &DeploymentValidator{store: store}
}

// ValidationResult contains bytecode-extracted metadata. The Allowed
// flag is always true post-M10 — the actual security gate moved to
// runtime trace. The metadata fields remain because the proxy auto-
// registration flow consumes them.
type ValidationResult struct {
	Allowed         bool     // Always true post-M10. Kept for interface compatibility.
	Reason          string   // Always empty post-M10. Kept for interface compatibility.
	ConstantTargets []string // Addresses the contract will call. Informational only.
	HasDynamicCalls bool     // Whether contract has dynamic call targets. Informational only.
	HasCreate       bool     // Whether contract uses CREATE
	HasCreate2      bool     // Whether contract uses CREATE2

	// Proxy detection fields — consumed by jsonrpc_processor for
	// proxy auto-registration. These are why DeploymentValidator
	// continues to exist.
	IsProxy   bool                // Whether this is a proxy contract
	ProxyType string              // Type of proxy if applicable (e.g., "ERC1967", "Transparent", "UUPS")
	ProxyInfo *bytecode.ProxyInfo // Full proxy detection info

	// Constructor validation fields. Post-M10 these are informational
	// only — runtime tracing validates every executed frame.
	ConstructorAddresses []string // Addresses found in constructor arguments
	ConstructorValidated bool     // Always false post-M10. Kept for interface compatibility.
	HasConstructorArgs   bool     // Whether bytecode has constructor arguments
}

// ValidateDeployment extracts bytecode metadata for a contract
// deployment. Post-M10 the call-target validation is gone — the
// runtime trace in jsonrpc_processor.validateDeployWithTracing is the
// authoritative gate. This function returns the extracted metadata
// (HasCreate, HasCreate2, IsProxy, ProxyType, ProxyInfo) so the
// proxy auto-registration pipeline still has what it needs.
//
// The hasAdminClaim parameter is retained for interface compatibility
// but ignored — admin claim was a workaround for the now-deleted
// static "no CREATE/CREATE2 unless admin" rule.
func (v *DeploymentValidator) ValidateDeployment(
	ctx context.Context,
	orgID string,
	bytecodeHex string,
	hasAdminClaim bool,
) (*ValidationResult, error) {
	_ = ctx
	_ = orgID
	_ = hasAdminClaim

	bcOriginal, err := bytecode.ParseHex(bytecodeHex)
	if err != nil {
		// Malformed bytecode never makes it to a node that would accept
		// it as a deploy, so reject here as a cheap early-bail.
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	// Empty bytecode is a degenerate case (zero-length init code). Let
	// it through — the runtime trace will see a CREATE frame with no
	// nested frames and validate the deploy-claim gate.
	if bcOriginal.IsEmpty() {
		return &ValidationResult{Allowed: true}, nil
	}

	// CBOR-strip for opcode analysis: Solidity's CBOR metadata at the
	// end of contracts can contain bytes that look like opcodes
	// (0xf0 = CREATE, 0xf5 = CREATE2, 0x73 = PUSH20 = 's' in "solc") but
	// are just data, not executable code. The proxy detector and
	// CREATE/CREATE2 flags would false-positive without stripping.
	bc, err := bytecode.ParseHexForAnalysis(bytecodeHex)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	analysis := bytecode.ExtractCallTargets(bc)
	proxyInfo := bytecode.DetectProxyPattern(bc)

	return &ValidationResult{
		Allowed:         true,
		ConstantTargets: analysis.ConstantAddrs,
		HasDynamicCalls: analysis.HasDynamicCall,
		HasCreate:       analysis.HasCreate,
		HasCreate2:      analysis.HasCreate2,
		IsProxy:         proxyInfo.IsProxy,
		ProxyType:       string(proxyInfo.ProxyType),
		ProxyInfo:       proxyInfo,
	}, nil
}

// ValidateDeploymentWithABI is the historical entry point that also
// took a constructor ABI for argument validation. Post-M10 the ABI
// parameter is ignored — the runtime trace handles every cross-org
// access, including those passed in as constructor arguments. Returns
// the same metadata as ValidateDeployment.
//
// Kept on the surface so callers don't need to be updated in
// lockstep; future cleanup may drop this in favor of
// ValidateDeployment alone.
func (v *DeploymentValidator) ValidateDeploymentWithABI(
	ctx context.Context,
	orgID string,
	bytecodeHex string,
	constructorABI string,
	hasAdminClaim bool,
) (*ValidationResult, error) {
	_ = constructorABI
	return v.ValidateDeployment(ctx, orgID, bytecodeHex, hasAdminClaim)
}
