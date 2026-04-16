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

	// Constructor validation fields
	ConstructorAddresses []string // Addresses found in constructor arguments
	ConstructorValidated bool     // Whether constructor args were validated
	HasConstructorArgs   bool     // Whether bytecode has constructor arguments
}

// ValidateDeployment checks if a contract deployment is allowed.
// It analyzes the bytecode to ensure:
// 1. Trusted factory detection (CREATE/CREATE2 allowed for whitelisted factories)
// 2. All constant call targets are allowed for the org
//
// Dynamic calls and CREATE/CREATE2 are allowed because runtime tracing validates
// them at execution time via debug_traceCall.
//
// The hasAdminClaim parameter allows admin users to deploy factory contracts
// that contain CREATE/CREATE2 opcodes.
func (v *DeploymentValidator) ValidateDeployment(
	ctx context.Context,
	orgID string,
	bytecodeHex string,
	hasAdminClaim bool,
) (*ValidationResult, error) {
	// Parse bytecode twice:
	// 1. Original (for trusted factory hash check - hash includes CBOR metadata)
	// 2. CBOR-stripped (for opcode analysis - CBOR metadata can look like opcodes)
	bcOriginal, err := bytecode.ParseHex(bytecodeHex)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	// Handle empty bytecode
	if bcOriginal.IsEmpty() {
		return &ValidationResult{
			Allowed: true,
			Reason:  "",
		}, nil
	}

	// Parse again with CBOR stripping for security analysis.
	// This is important because Solidity's CBOR metadata at the end of contracts
	// can contain bytes that look like opcodes (e.g., 0xf0 = CREATE, 0xf5 = CREATE2,
	// 0x73 = PUSH20 which is 's' in "solc") but are actually just data, not executable code.
	bc, err := bytecode.ParseHexForAnalysis(bytecodeHex)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	// Analyze CBOR-stripped bytecode for call targets
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

	// Check 1: Detect trusted factory contracts with CREATE/CREATE2
	// Note: Trusted factory deployment still requires admin claim (checked in access.go)
	_ = hasAdminClaim // Silence unused warning
	if analysis.HasCreate || analysis.HasCreate2 {
		// Check if this is a trusted factory contract
		// Use the ORIGINAL bytecode (with CBOR) for hash checking since the
		// trusted factory hash was computed from the original bytecode.
		trustedFactory := create3.IsTrustedFactoryBytecode(bcOriginal.Raw)
		if trustedFactory != nil {
			// This is a whitelisted factory - allow it (admin check happens in access.go)
			result.IsTrustedFactory = true
			result.FactoryName = trustedFactory.Name
			result.Allowed = true
			return result, nil
		}
		// Non-trusted CREATE/CREATE2 are allowed — runtime tracing validates
		// the actual execution and auto-registers created addresses.
	}

	// Check 2: Verify all constant call targets are allowed
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

// ValidateDeploymentWithABI validates a deployment with constructor argument validation.
// If the bytecode has constructor arguments (trailing bytes after opcodes), the ABI is REQUIRED.
// If no constructor arguments exist, the ABI is optional.
//
// This method performs all the same validations as ValidateDeployment, plus:
// - Detects if bytecode has constructor arguments
// - If args exist and no ABI provided: skips constructor validation (runtime tracing catches cross-org calls)
// - If args exist and ABI provided: decodes args and validates any addresses
//
// The hasAdminClaim parameter allows admin users to deploy factory contracts.
func (v *DeploymentValidator) ValidateDeploymentWithABI(
	ctx context.Context,
	orgID string,
	bytecodeHex string,
	constructorABI string,
	hasAdminClaim bool,
) (*ValidationResult, error) {
	// Parse bytecode twice:
	// 1. Original (for trusted factory hash check - hash includes CBOR metadata)
	// 2. CBOR-stripped (for opcode analysis - CBOR metadata can look like opcodes)
	bcOriginal, err := bytecode.ParseHex(bytecodeHex)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	// Handle empty bytecode
	if bcOriginal.IsEmpty() {
		return &ValidationResult{
			Allowed: true,
			Reason:  "",
		}, nil
	}

	// Parse again with CBOR stripping for security analysis.
	bc, err := bytecode.ParseHexForAnalysis(bytecodeHex)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Reason:  "invalid bytecode: " + err.Error(),
		}, nil
	}

	// Analyze CBOR-stripped bytecode for call targets
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

	// Check 1: Detect trusted factory contracts with CREATE/CREATE2
	_ = hasAdminClaim // Silence unused warning
	if analysis.HasCreate || analysis.HasCreate2 {
		trustedFactory := create3.IsTrustedFactoryBytecode(bcOriginal.Raw)
		if trustedFactory != nil {
			result.IsTrustedFactory = true
			result.FactoryName = trustedFactory.Name
			result.Allowed = true
			return result, nil
		}
		// Non-trusted CREATE/CREATE2 are allowed — runtime tracing validates at execution time.
	}

	// Check 2: Verify all constant call targets are allowed
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

	// Check 3: Constructor argument validation
	// When no ABI is provided, skip constructor validation — runtime tracing
	// will catch any cross-org calls at execution time.
	if constructorABI == "" {
		result.ConstructorValidated = false
		result.HasConstructorArgs = false
		result.Allowed = true
		return result, nil
	}

	constructorResult, err := bytecode.ExtractConstructorArgs(bc.Raw, constructorABI)
	if err != nil {
		result.Allowed = false
		result.Reason = err.Error()
		return result, nil
	}

	result.ConstructorAddresses = constructorResult.Addresses
	result.ConstructorValidated = true
	result.HasConstructorArgs = constructorResult.HasArgs

	// Validate each address from constructor args
	for _, addr := range constructorResult.Addresses {
		// Precompiles are always allowed
		if precompile.IsPrecompileAddress(addr) {
			continue
		}

		allowed, err := v.isAddressAllowedForOrg(ctx, addr, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to check constructor arg address: %w", err)
		}
		if !allowed {
			result.Allowed = false
			result.Reason = fmt.Sprintf("constructor argument contains address %s not allowed for org", addr)
			return result, nil
		}
	}

	result.Allowed = true
	return result, nil
}

// isAddressAllowedForOrg checks if an address can be called by contracts in the org.
// An address is allowed if:
// 1. It is owned by this org (already deployed by the org), OR
// 2. It is preregistered for this org (whitelisted for deployment)
//
// Note: Precompile addresses are checked before this function is called.
func (v *DeploymentValidator) isAddressAllowedForOrg(ctx context.Context, addr, orgID string) (bool, error) {
	// Check if address is owned by this org (already deployed contract)
	owned, err := v.store.IsAddressOwnedByOrg(ctx, addr, orgID)
	if err != nil {
		return false, err
	}
	if owned {
		return true, nil
	}

	// Check if address is preregistered for this org (whitelisted for deployment)
	preregistered, err := v.store.IsAddressPreregistered(ctx, orgID, addr)
	if err != nil {
		return false, err
	}
	if preregistered {
		return true, nil
	}

	// Address is neither owned nor preregistered - deny
	return false, nil
}
