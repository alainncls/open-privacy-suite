package rbac

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"privacy-proxy/internal/evm/create3"
)

// CREATE3 factory deploy function selector
// deploy(bytes32 salt, bytes calldata creationCode) returns (address)
// Selector: keccak256("deploy(bytes32,bytes)")[:4] = 0xcdcb760a
const (
	SelectorCreate3Deploy = "cdcb760a"
)

// FactoryCallValidator validates calls to CREATE3 factory contracts.
// It ensures that:
// 1. The target address of deployment is preregistered for the org
// 2. The creation bytecode passes deployment validation (no unsafe calls)
type FactoryCallValidator struct {
	store           Store
	deployValidator *DeploymentValidator
}

// NewFactoryCallValidator creates a new factory call validator.
func NewFactoryCallValidator(store Store, deployValidator *DeploymentValidator) *FactoryCallValidator {
	return &FactoryCallValidator{
		store:           store,
		deployValidator: deployValidator,
	}
}

// FactoryCallValidationResult contains the result of factory call validation.
type FactoryCallValidationResult struct {
	IsFactoryCall     bool   // Whether this is a call to the org's factory
	IsDeployCall      bool   // Whether this is a deploy() call
	Allowed           bool   // Whether the call is allowed
	Reason            string // Reason for denial (if not allowed)
	TargetAddress     string // The calculated CREATE3 address
	Salt              string // The salt from calldata
	CreationBytecode  string // The creation bytecode from calldata
	BytecodeValidated bool   // Whether bytecode was validated
}

// ValidateFactoryCall checks if a call to a factory contract is allowed.
// This should be called when:
// - Target address matches the org's configured factory
// - Method is eth_sendTransaction
//
// Parameters:
//   - ctx: Context
//   - orgID: The organization ID
//   - factoryAddress: The org's configured factory address
//   - targetAddress: The address being called
//   - calldata: The transaction calldata
//
// Returns validation result indicating whether the call is allowed.
func (v *FactoryCallValidator) ValidateFactoryCall(
	ctx context.Context,
	orgID string,
	factoryAddress string,
	targetAddress string,
	calldata []byte,
) (*FactoryCallValidationResult, error) {
	result := &FactoryCallValidationResult{}

	// Normalize addresses for comparison
	factoryAddr := strings.ToLower(strings.TrimPrefix(factoryAddress, "0x"))
	targetAddr := strings.ToLower(strings.TrimPrefix(targetAddress, "0x"))

	// Check if this is a call to the org's factory
	if factoryAddr != targetAddr {
		result.IsFactoryCall = false
		result.Allowed = true // Not a factory call, let other validators handle it
		return result, nil
	}

	result.IsFactoryCall = true

	// Check if calldata matches deploy() selector
	if len(calldata) < 4 {
		result.IsDeployCall = false
		result.Allowed = true // Not enough data for a function call
		return result, nil
	}

	selector := hex.EncodeToString(calldata[:4])
	if selector != SelectorCreate3Deploy {
		result.IsDeployCall = false
		result.Allowed = true // Not a deploy call, allow other functions on factory
		return result, nil
	}

	result.IsDeployCall = true

	// Parse the deploy() calldata
	// ABI encoding: selector (4 bytes) + salt (32 bytes) + offset (32 bytes) + length (32 bytes) + data
	if len(calldata) < 100 { // 4 + 32 + 32 + 32 minimum
		result.Allowed = false
		result.Reason = "deploy() calldata too short"
		return result, nil
	}

	// Extract salt (bytes 4-36)
	salt := calldata[4:36]
	result.Salt = "0x" + hex.EncodeToString(salt)

	// Extract creation bytecode
	// Offset is at bytes 36-68 (pointing to where the bytes data starts)
	// The offset should point to position 64 (0x40) from the start of parameters
	// Length is at that offset, then data follows

	// For simplicity, let's parse the dynamic bytes parameter
	creationBytecode, err := extractBytesParameter(calldata[4:], 32) // offset starts after salt
	if err != nil {
		result.Allowed = false
		result.Reason = fmt.Sprintf("failed to parse creation bytecode: %v", err)
		return result, nil
	}
	result.CreationBytecode = "0x" + hex.EncodeToString(creationBytecode)

	// Calculate the target CREATE3 address
	var saltArray [32]byte
	copy(saltArray[:], salt)

	factoryAddrFull := "0x" + factoryAddr
	targetCreate3Addr, err := create3.CalculateCREATE3AddressFromHex(factoryAddrFull, result.Salt)
	if err != nil {
		result.Allowed = false
		result.Reason = fmt.Sprintf("failed to calculate CREATE3 address: %v", err)
		return result, nil
	}
	result.TargetAddress = strings.ToLower(targetCreate3Addr.Hex())

	// Check if the target address is preregistered for this org
	isPreregistered, err := v.store.IsAddressPreregistered(ctx, orgID, result.TargetAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check preregistered address: %w", err)
	}

	if !isPreregistered {
		result.Allowed = false
		result.Reason = fmt.Sprintf("target address %s is not preregistered for this organization", result.TargetAddress)
		return result, nil
	}

	// Validate the creation bytecode
	if len(creationBytecode) > 0 {
		bytecodeHex := "0x" + hex.EncodeToString(creationBytecode)
		// Pass false for hasAdminClaim - factory call validation has its own CREATE/CREATE2 handling
		validationResult, err := v.deployValidator.ValidateDeployment(ctx, orgID, bytecodeHex, false)
		if err != nil {
			return nil, fmt.Errorf("failed to validate creation bytecode: %w", err)
		}

		result.BytecodeValidated = true

		if !validationResult.Allowed {
			result.Allowed = false
			result.Reason = fmt.Sprintf("creation bytecode validation failed: %s", validationResult.Reason)
			return result, nil
		}

		// For factory deployments, we don't require admin claim for the bytecode itself
		// (that's only for deploying the factory contract directly)
		// But we still block untrusted factory patterns in the creation code
		if validationResult.HasCreate || validationResult.HasCreate2 {
			if !validationResult.IsTrustedFactory {
				result.Allowed = false
				result.Reason = "creation bytecode contains CREATE/CREATE2 opcodes but is not a trusted factory"
				return result, nil
			}
		}
	}

	result.Allowed = true
	return result, nil
}

// extractBytesParameter extracts a dynamic bytes parameter from ABI-encoded data.
// offsetPosition is the position in data where the offset to the bytes data is stored.
func extractBytesParameter(data []byte, offsetPosition int) ([]byte, error) {
	if len(data) < offsetPosition+32 {
		return nil, fmt.Errorf("data too short to read offset")
	}

	// Read the offset (big-endian uint256, but we only care about last 4 bytes for reasonable sizes)
	offsetBytes := data[offsetPosition : offsetPosition+32]
	offset := int(offsetBytes[31]) | int(offsetBytes[30])<<8 | int(offsetBytes[29])<<16 | int(offsetBytes[28])<<24

	// The offset is relative to the start of the parameters (after selector)
	// So the length is at data[offset:offset+32]
	if len(data) < offset+32 {
		return nil, fmt.Errorf("data too short to read length at offset %d", offset)
	}

	lengthBytes := data[offset : offset+32]
	length := int(lengthBytes[31]) | int(lengthBytes[30])<<8 | int(lengthBytes[29])<<16 | int(lengthBytes[28])<<24

	// The actual bytes data starts at offset+32
	dataStart := offset + 32
	if len(data) < dataStart+length {
		return nil, fmt.Errorf("data too short to read bytes of length %d at position %d", length, dataStart)
	}

	return data[dataStart : dataStart+length], nil
}

// IsCreate3DeploySelector checks if a function selector matches the CREATE3 deploy function.
func IsCreate3DeploySelector(selector string) bool {
	selector = strings.TrimPrefix(strings.ToLower(selector), "0x")
	return selector == SelectorCreate3Deploy
}

// GetOrgFactoryAddress retrieves the configured factory address for an organization.
// Returns empty string if no factory is configured.
func GetOrgFactoryAddress(org *Organization) string {
	if org == nil || org.Settings == nil {
		return ""
	}

	factoryAddr, ok := org.Settings["factory_address"].(string)
	if !ok {
		return ""
	}

	return strings.ToLower(factoryAddr)
}
