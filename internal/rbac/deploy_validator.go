package rbac

import (
	"context"
	"fmt"
	"strings"

	"privacy-proxy/internal/evm/bytecode"
	"privacy-proxy/internal/evm/create3"
	"privacy-proxy/internal/evm/precompile"
)

// DeploymentValidator validates contract deployments against org security rules.
type DeploymentValidator struct {
	store Store
}

// NewDeploymentValidator creates a new deployment validator.
func NewDeploymentValidator(store Store) *DeploymentValidator {
	return &DeploymentValidator{store: store}
}

// ValidationResult contains the result of deployment validation.
type ValidationResult struct {
	Allowed         bool     // Whether the deployment is allowed
	Reason          string   // Reason for denial (if not allowed)
	ConstantTargets []string // Addresses the contract will call
	HasDynamicCalls bool     // Whether contract has dynamic call targets
	HasCreate       bool     // Whether contract uses CREATE
	HasCreate2      bool     // Whether contract uses CREATE2

	// Proxy detection fields
	IsProxy   bool                // Whether this is a proxy contract
	ProxyType string              // Type of proxy if applicable (e.g., "ERC1967", "Transparent", "UUPS")
	ProxyInfo *bytecode.ProxyInfo // Full proxy detection info

	// Factory detection fields
	IsTrustedFactory bool   // Whether this is a whitelisted factory contract
	FactoryName      string // Name of the factory if whitelisted
}

// ValidateDeployment checks if a contract deployment is allowed.
// It analyzes the bytecode to ensure:
// 1. No CREATE/CREATE2 opcodes (prevents nested deployments)
// 2. No dynamic call targets (addresses from storage/calldata)
// 3. All constant call targets are allowed for the org
func (v *DeploymentValidator) ValidateDeployment(
	ctx context.Context,
	orgID string,
	bytecodeHex string,
) (*ValidationResult, error) {
	// Parse bytecode
	bc, err := bytecode.ParseHex(bytecodeHex)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	// Handle empty bytecode
	if bc.IsEmpty() {
		return &ValidationResult{
			Allowed: true,
			Reason:  "",
		}, nil
	}

	// Analyze bytecode for call targets
	analysis := bytecode.ExtractCallTargets(bc)

	// Detect if this is a proxy contract
	proxyInfo := bytecode.DetectProxyPattern(bc)

	result := &ValidationResult{
		ConstantTargets: analysis.ConstantAddrs,
		HasDynamicCalls: analysis.HasDynamicCall,
		HasCreate:       analysis.HasCreate,
		HasCreate2:      analysis.HasCreate2,
		IsProxy:         proxyInfo.IsProxy,
		ProxyType:       string(proxyInfo.ProxyType),
		ProxyInfo:       proxyInfo,
	}

	// Check 1: Block contracts with CREATE/CREATE2 (prevents nested deployments)
	// Exception: Whitelisted factory contracts (e.g., CREATE3 factories) are allowed
	if analysis.HasCreate || analysis.HasCreate2 {
		// Check if this is a trusted factory contract
		trustedFactory := create3.IsTrustedFactoryBytecode(bc.Raw)
		if trustedFactory != nil {
			// This is a whitelisted factory - allow it
			result.IsTrustedFactory = true
			result.FactoryName = trustedFactory.Name
			result.Allowed = true
			return result, nil
		}

		result.Allowed = false
		result.Reason = "contract contains CREATE/CREATE2 opcodes (nested deployments not allowed)"
		return result, nil
	}

	// Check 2: Block contracts with dynamic call targets
	// Exception: Proxy contracts are expected to have dynamic DELEGATECALL patterns
	// (they load the implementation address from storage and delegatecall to it)
	if analysis.HasDynamicCall && !proxyInfo.IsProxy {
		result.Allowed = false
		result.Reason = "contract contains dynamic external calls (address from storage/calldata)"
		return result, nil
	}

	// Check 3: Verify all constant call targets are allowed
	for _, target := range analysis.CallTargets {
		if target.TargetType != bytecode.CallTargetConstant {
			continue
		}

		addr := strings.ToLower(target.Address)

		// Precompiles are always allowed
		if precompile.IsPrecompileAddress(addr) {
			continue
		}

		// DELEGATECALL requires org ownership (library must be org-owned)
		if target.OpcodeName == "DELEGATECALL" {
			owned, err := v.store.IsAddressOwnedByOrg(ctx, addr, orgID)
			if err != nil {
				return nil, fmt.Errorf("failed to check DELEGATECALL target ownership: %w", err)
			}
			if !owned {
				result.Allowed = false
				result.Reason = fmt.Sprintf("DELEGATECALL target %s must be owned by org", addr)
				return result, nil
			}
			continue
		}

		// Regular CALL: target must be org-owned or truly public
		allowed, err := v.isAddressAllowedForOrg(ctx, addr, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to check CALL target: %w", err)
		}
		if !allowed {
			result.Allowed = false
			result.Reason = fmt.Sprintf("call target %s not allowed for org", addr)
			return result, nil
		}
	}

	result.Allowed = true
	return result, nil
}

// isAddressAllowedForOrg checks if an address can be called by contracts in the org.
// An address is allowed if:
// 1. It is owned by this org, OR
// 2. It is not registered to ANY org (truly public contract)
func (v *DeploymentValidator) isAddressAllowedForOrg(ctx context.Context, addr, orgID string) (bool, error) {
	// Check if address is owned by this org
	owned, err := v.store.IsAddressOwnedByOrg(ctx, addr, orgID)
	if err != nil {
		return false, err
	}
	if owned {
		return true, nil
	}

	// Check if address is registered to ANY org (if so, not allowed - belongs to other org)
	registeredToAnyOrg, err := v.store.IsContractRegisteredToAnyOrg(ctx, addr)
	if err != nil {
		return false, err
	}
	if registeredToAnyOrg {
		return false, nil // Belongs to another org
	}

	// Not registered to any org - it's a public contract, allow
	return true, nil
}

// RegisterDeployedProxy registers a deployed proxy contract for upgrade interception.
// This should be called by the caller (access controller or RPC handler) after the
// deployment transaction succeeds, not during validation.
//
// Parameters:
//   - orgID: The organization that owns the proxy
//   - proxyAddress: The deployed proxy contract address (will be normalized to lowercase)
//   - proxyInfo: The proxy detection info from validation (contains proxy type and slots)
//   - initialImpl: The initial implementation address (if known, empty string if not detectable)
func (v *DeploymentValidator) RegisterDeployedProxy(
	ctx context.Context,
	orgID string,
	proxyAddress string,
	proxyInfo *bytecode.ProxyInfo,
	initialImpl string,
) error {
	if proxyInfo == nil || !proxyInfo.IsProxy {
		return fmt.Errorf("cannot register non-proxy contract as managed proxy")
	}

	// Normalize addresses to lowercase with 0x prefix
	normalizedProxyAddr := strings.ToLower(proxyAddress)
	if !strings.HasPrefix(normalizedProxyAddr, "0x") {
		normalizedProxyAddr = "0x" + normalizedProxyAddr
	}

	normalizedImpl := strings.ToLower(initialImpl)
	if normalizedImpl != "" && !strings.HasPrefix(normalizedImpl, "0x") {
		normalizedImpl = "0x" + normalizedImpl
	}

	proxy := &ManagedProxy{
		OrgID:        orgID,
		ProxyAddress: normalizedProxyAddr,
		ProxyType:    string(proxyInfo.ProxyType),
		CurrentImpl:  normalizedImpl,
	}

	return v.store.CreateManagedProxy(ctx, proxy)
}
