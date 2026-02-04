// Package bytecode provides EVM bytecode analysis utilities.
package bytecode

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ConstructorArgsResult contains extracted constructor argument information.
type ConstructorArgsResult struct {
	// Addresses extracted from constructor arguments (lowercase, 0x-prefixed)
	Addresses []string

	// ArgsOffset is the byte offset where constructor arguments begin in init code.
	// If ArgsOffset == len(initCode), there are no constructor arguments.
	ArgsOffset int

	// HasArgs indicates whether the ABI declares constructor arguments
	HasArgs bool

	// DecodedArgs contains all decoded arguments with their types (if ABI was provided)
	DecodedArgs []DecodedArg
}

// DecodedArg represents a single decoded constructor argument.
type DecodedArg struct {
	Name      string // Parameter name from ABI
	Type      string // ABI type string (e.g., "address", "uint256")
	Value     any    // Decoded value
	IsAddress bool   // True if this argument contains address type(s)
}

// ExtractConstructorArgs extracts and decodes constructor arguments from init code.
//
// The function uses the ABI to determine the size and structure of constructor arguments,
// then extracts them from the END of the bytecode.
//
// If ABI is provided with constructor inputs:
//   - Calculates expected size based on ABI types
//   - Extracts that many bytes from the end of bytecode
//   - Decodes and validates addresses
//
// If ABI is provided with no constructor inputs:
//   - Returns empty result (no addresses to validate)
//
// If ABI is NOT provided:
//   - Returns error (ABI is required for security)
func ExtractConstructorArgs(initCode []byte, abiJSON string) (*ConstructorArgsResult, error) {
	result := &ConstructorArgsResult{
		ArgsOffset: len(initCode),
		HasArgs:    false,
	}

	// ABI is required for secure validation
	if abiJSON == "" {
		return nil, errors.New("ABI is required for constructor argument validation")
	}

	// Parse ABI
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("invalid ABI JSON: %w", err)
	}

	// Check if ABI has constructor with inputs
	if len(parsedABI.Constructor.Inputs) == 0 {
		// ABI says no constructor args - nothing to validate
		return result, nil
	}

	result.HasArgs = true

	// Calculate the size of constructor arguments based on ABI types
	argsSize, err := calculateABIEncodedSize(parsedABI.Constructor.Inputs)
	if err != nil {
		return nil, fmt.Errorf("cannot calculate constructor args size: %w", err)
	}

	if argsSize > len(initCode) {
		return nil, fmt.Errorf("constructor args size (%d) exceeds bytecode length (%d)", argsSize, len(initCode))
	}

	// Extract constructor args from the END of bytecode
	argsOffset := len(initCode) - argsSize
	args := initCode[argsOffset:]
	result.ArgsOffset = argsOffset

	// Decode constructor arguments
	values, err := parsedABI.Constructor.Inputs.Unpack(args)
	if err != nil {
		return nil, fmt.Errorf("failed to decode constructor args: %w", err)
	}

	// Extract addresses from decoded values
	result.DecodedArgs = make([]DecodedArg, len(values))
	for i, input := range parsedABI.Constructor.Inputs {
		arg := DecodedArg{
			Name:  input.Name,
			Type:  input.Type.String(),
			Value: values[i],
		}

		addrs := extractAddressesFromValue(input.Type, values[i])
		if len(addrs) > 0 {
			arg.IsAddress = true
			result.Addresses = append(result.Addresses, addrs...)
		}

		result.DecodedArgs[i] = arg
	}

	return result, nil
}

// calculateABIEncodedSize calculates the byte size of ABI-encoded arguments.
// For fixed-size types, this is deterministic (32 bytes each).
// For dynamic types (bytes, string, T[]), returns an error as size is variable.
func calculateABIEncodedSize(inputs abi.Arguments) (int, error) {
	size := 0
	for _, input := range inputs {
		typeSize, err := getTypeSize(input.Type)
		if err != nil {
			return 0, err
		}
		size += typeSize
	}
	return size, nil
}

// getTypeSize returns the ABI-encoded size of a type.
// Returns error for dynamic types.
func getTypeSize(t abi.Type) (int, error) {
	switch t.T {
	case abi.IntTy, abi.UintTy, abi.BoolTy, abi.AddressTy,
		abi.FixedBytesTy, abi.FunctionTy:
		// All fixed-size types are encoded as 32 bytes
		return 32, nil

	case abi.ArrayTy:
		// Fixed-size arrays: element size * array length
		if t.Elem == nil {
			return 0, fmt.Errorf("array type has no element type")
		}
		elemSize, err := getTypeSize(*t.Elem)
		if err != nil {
			return 0, err
		}
		return elemSize * t.Size, nil

	case abi.TupleTy:
		// Tuples: sum of all element sizes (if all are fixed)
		totalSize := 0
		for _, elem := range t.TupleElems {
			if elem == nil {
				continue
			}
			elemSize, err := getTypeSize(*elem)
			if err != nil {
				return 0, err
			}
			totalSize += elemSize
		}
		return totalSize, nil

	case abi.BytesTy, abi.StringTy, abi.SliceTy:
		// Dynamic types - cannot determine size statically
		return 0, fmt.Errorf("dynamic type %s not supported for constructor validation - size cannot be determined statically", t.String())

	default:
		return 0, fmt.Errorf("unknown ABI type: %v", t.T)
	}
}

// HasConstructorArgs returns true if the ABI declares constructor inputs.
// This is the secure way to check - based on ABI, not bytecode analysis.
func HasConstructorArgs(bc *Bytecode) bool {
	// This function is kept for API compatibility but should not be used
	// for security decisions. Use ExtractConstructorArgs with ABI instead.
	// Always returns false since we can't reliably detect args without ABI.
	return false
}

// extractAddressesFromValue recursively extracts addresses from a decoded ABI value.
// Handles address, address[], address[N], and nested structs containing addresses.
func extractAddressesFromValue(typ abi.Type, value any) []string {
	var addresses []string

	switch typ.T {
	case abi.AddressTy:
		if addr, ok := value.(common.Address); ok {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}

	case abi.ArrayTy:
		// Handle fixed-size arrays: address[N]
		if typ.Elem != nil && typ.Elem.T == abi.AddressTy {
			// go-ethereum unpacks fixed arrays as [N]common.Address
			// We need to use reflection to handle any size
			addresses = append(addresses, extractAddressesFromFixedArray(value)...)
		}

	case abi.SliceTy:
		// Handle dynamic arrays: address[]
		if typ.Elem != nil && typ.Elem.T == abi.AddressTy {
			if addrs, ok := value.([]common.Address); ok {
				for _, addr := range addrs {
					addresses = append(addresses, strings.ToLower(addr.Hex()))
				}
			}
		}

	case abi.TupleTy:
		// Handle structs containing addresses
		// go-ethereum unpacks tuples as anonymous structs
		// We need reflection to extract fields
		addresses = append(addresses, extractAddressesFromTuple(typ, value)...)
	}

	return addresses
}

// extractAddressesFromFixedArray extracts addresses from a fixed-size array.
// go-ethereum unpacks fixed arrays as [N]common.Address which requires reflection.
func extractAddressesFromFixedArray(value any) []string {
	var addresses []string

	// Use type switch for common sizes
	switch v := value.(type) {
	case [1]common.Address:
		for _, addr := range v {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	case [2]common.Address:
		for _, addr := range v {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	case [3]common.Address:
		for _, addr := range v {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	case [4]common.Address:
		for _, addr := range v {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	case [5]common.Address:
		for _, addr := range v {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	case [10]common.Address:
		for _, addr := range v {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	default:
		// For other sizes, use reflection
		addresses = append(addresses, extractAddressesWithReflection(value)...)
	}

	return addresses
}

// extractAddressesFromTuple extracts addresses from a tuple/struct type.
// Uses the type definition to iterate through components.
func extractAddressesFromTuple(typ abi.Type, value any) []string {
	var addresses []string

	if len(typ.TupleElems) == 0 {
		return addresses
	}

	// go-ethereum unpacks tuples as slices of any
	if values, ok := value.([]any); ok {
		for i, elem := range typ.TupleElems {
			if i < len(values) {
				addrs := extractAddressesFromValue(*elem, values[i])
				addresses = append(addresses, addrs...)
			}
		}
	}

	return addresses
}

// extractAddressesWithReflection uses reflection to extract addresses from arrays.
// This is a fallback for array sizes not covered by the type switch.
func extractAddressesWithReflection(value any) []string {
	var addresses []string

	// Use reflection to handle arbitrary array sizes
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Array {
		return addresses
	}

	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i).Interface()
		if addr, ok := elem.(common.Address); ok {
			addresses = append(addresses, strings.ToLower(addr.Hex()))
		}
	}

	return addresses
}
