package bytecode

import (
	"encoding/hex"
	"strings"
)

// CallTargetType represents the type of call target detection.
type CallTargetType string

const (
	// CallTargetConstant indicates a constant (hardcoded) address.
	CallTargetConstant CallTargetType = "constant"
	// CallTargetDynamic indicates an address loaded from storage, memory, or calldata.
	CallTargetDynamic CallTargetType = "dynamic"
	// CallTargetUnknown indicates the address source could not be determined.
	CallTargetUnknown CallTargetType = "unknown"
)

// CallTarget represents a detected external call in bytecode.
type CallTarget struct {
	Offset     uint64         // Position in bytecode
	OpcodeName string         // CALL, DELEGATECALL, STATICCALL, CALLCODE
	TargetType CallTargetType // "constant", "dynamic", "unknown"
	Address    string         // Hex address if constant, empty otherwise
	SourceOp   string         // What provides the address: "PUSH20", "SLOAD", etc.
}

// AnalysisResult contains the results of bytecode analysis.
type AnalysisResult struct {
	CallTargets    []CallTarget // All detected call targets
	HasDynamicCall bool         // True if any dynamic call targets found
	ConstantAddrs  []string     // All unique constant addresses found
	HasCreate      bool         // Contains CREATE opcode
	HasCreate2     bool         // Contains CREATE2 opcode
	HasSelfDestruct bool        // Contains SELFDESTRUCT opcode
	HasDelegateCall bool        // Contains DELEGATECALL opcode
}

// ExtractCallTargets analyzes bytecode to find all external call targets.
func ExtractCallTargets(bc *Bytecode) *AnalysisResult {
	result := &AnalysisResult{
		CallTargets:   make([]CallTarget, 0),
		ConstantAddrs: make([]string, 0),
	}

	if bc == nil || len(bc.Opcodes) == 0 {
		return result
	}

	// Check for CREATE/CREATE2/SELFDESTRUCT
	result.HasCreate = bc.HasOpcode(CREATE)
	result.HasCreate2 = bc.HasOpcode(CREATE2)
	result.HasSelfDestruct = bc.HasOpcode(SELFDESTRUCT)
	result.HasDelegateCall = bc.HasOpcode(DELEGATECALL)

	// Find all call opcodes and analyze their targets
	for i, op := range bc.Opcodes {
		if !IsCallOpcode(op.Code) {
			continue
		}

		target := CallTarget{
			Offset:     op.Offset,
			OpcodeName: op.Name,
			TargetType: CallTargetUnknown,
		}

		// Try to find the address source by looking backwards
		// CALL stack: gas, addr, value, argsOffset, argsLength, retOffset, retLength
		// STATICCALL/DELEGATECALL: gas, addr, argsOffset, argsLength, retOffset, retLength
		// The address is the 2nd stack element (after gas)

		addr, sourceOp := findAddressSource(bc.Opcodes, i)
		if addr != "" {
			target.TargetType = CallTargetConstant
			target.Address = addr
			target.SourceOp = sourceOp

			// Add to unique addresses list
			if !containsString(result.ConstantAddrs, addr) {
				result.ConstantAddrs = append(result.ConstantAddrs, addr)
			}
		} else if sourceOp != "" {
			target.TargetType = CallTargetDynamic
			target.SourceOp = sourceOp
			result.HasDynamicCall = true
		} else {
			target.TargetType = CallTargetUnknown
			result.HasDynamicCall = true // Conservative: treat unknown as dynamic
		}

		result.CallTargets = append(result.CallTargets, target)
	}

	return result
}

// findAddressSource looks backwards from a CALL opcode to find where the address comes from.
// Returns the address (if constant) and the source opcode name.
func findAddressSource(opcodes []Opcode, callIndex int) (string, string) {
	// Use two windows:
	// - Small window (10 opcodes): Check for dynamic sources first (SLOAD, CALLDATALOAD, MLOAD)
	//   These are strong indicators that the address is loaded at runtime
	// - Large window (50 opcodes): Check for constant addresses (PUSH20/PUSH32)
	//   Solidity compiler can place these far from the CALL due to stack manipulation

	smallWindowStart := callIndex - 10
	if smallWindowStart < 0 {
		smallWindowStart = 0
	}

	largeWindowStart := callIndex - 50
	if largeWindowStart < 0 {
		largeWindowStart = 0
	}

	// First pass: check small window for dynamic sources
	// If we find SLOAD/CALLDATALOAD close to the CALL, it's likely the address source
	for i := callIndex - 1; i >= smallWindowStart; i-- {
		op := opcodes[i]

		if op.Code == SLOAD {
			return "", "SLOAD"
		}
		if op.Code == CALLDATALOAD {
			return "", "CALLDATALOAD"
		}
	}

	// Second pass: look for constant addresses in the larger window
	// Solidity compiler generates many intermediate operations between PUSH20 and CALL
	for i := callIndex - 1; i >= largeWindowStart; i-- {
		op := opcodes[i]

		// PUSH20 is the most common pattern for constant addresses
		if op.Code == PUSH20 {
			if len(op.Args) == 20 {
				addr := "0x" + hex.EncodeToString(op.Args)
				addrLower := strings.ToLower(addr)

				// Skip address masks (0xffffff...ffff) used by Solidity for type conversion
				// These are not actual call targets
				if addrLower == "0xffffffffffffffffffffffffffffffffffffffff" {
					continue
				}

				return addrLower, "PUSH20"
			}
		}

		// PUSH32 can also contain addresses (padded with zeros)
		if op.Code == PUSH32 {
			if len(op.Args) == 32 {
				// Check if the first 12 bytes are zeros (address is in last 20 bytes)
				isZeroPadded := true
				for j := 0; j < 12; j++ {
					if op.Args[j] != 0 {
						isZeroPadded = false
						break
					}
				}
				if isZeroPadded {
					addr := "0x" + hex.EncodeToString(op.Args[12:])
					addrLower := strings.ToLower(addr)

					// Skip address masks
					if addrLower == "0xffffffffffffffffffffffffffffffffffffffff" {
						continue
					}

					return addrLower, "PUSH32"
				}
			}
		}
	}

	// Third pass: check larger window for MLOAD
	// MLOAD is checked last because Solidity uses it for memory management,
	// but if no constant address is found, MLOAD might be the address source
	for i := callIndex - 1; i >= largeWindowStart; i-- {
		op := opcodes[i]
		if op.Code == MLOAD {
			return "", "MLOAD"
		}
	}

	return "", ""
}

// containsString checks if a string slice contains a specific string.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ExtractPush20Addresses extracts all 20-byte addresses from PUSH20 opcodes.
// This is useful for finding all hardcoded addresses in a contract.
func ExtractPush20Addresses(bc *Bytecode) []string {
	var addresses []string
	seen := make(map[string]bool)

	for _, op := range bc.Opcodes {
		if op.Code == PUSH20 && len(op.Args) == 20 {
			addr := strings.ToLower("0x" + hex.EncodeToString(op.Args))
			if !seen[addr] {
				seen[addr] = true
				addresses = append(addresses, addr)
			}
		}
	}

	return addresses
}

// SummarizeAnalysis returns a human-readable summary of the analysis result.
func (r *AnalysisResult) SummarizeAnalysis() map[string]interface{} {
	return map[string]interface{}{
		"total_calls":        len(r.CallTargets),
		"constant_addresses": r.ConstantAddrs,
		"has_dynamic_calls":  r.HasDynamicCall,
		"has_create":         r.HasCreate,
		"has_create2":        r.HasCreate2,
		"has_selfdestruct":   r.HasSelfDestruct,
		"has_delegatecall":   r.HasDelegateCall,
	}
}
