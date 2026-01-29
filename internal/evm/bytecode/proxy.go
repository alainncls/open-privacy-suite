package bytecode

import (
	"encoding/hex"
	"strings"
)

// ERC1967Slots maps the standard ERC-1967 storage slot hashes to their purposes.
// These slots are used by upgradeable proxy contracts to store implementation,
// admin, and beacon addresses in predictable locations.
var ERC1967Slots = map[string]string{
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "implementation",
	"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "admin",
	"0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "beacon",
}

// UpgradeSelectors maps function selectors to their signatures for common upgrade functions.
// These selectors are used to identify upgrade capabilities in proxy contracts.
var UpgradeSelectors = map[string]string{
	"0x3659cfe6": "upgradeTo(address)",
	"0x4f1ef286": "upgradeToAndCall(address,bytes)",
	"0x5c60da1b": "implementation()",
	"0xf851a440": "admin()",
}

// DiamondSelectors maps function selectors specific to Diamond (EIP-2535) proxies.
var DiamondSelectors = map[string]string{
	"0x1f931c1c": "diamondCut((address,uint8,bytes4[])[],address,bytes)",
	"0x7a0ed627": "facets()",
	"0xcdffacc6": "facetAddress(bytes4)",
	"0x52ef6b2c": "facetAddresses()",
	"0xadfca15e": "facetFunctionSelectors(address)",
}

// DiamondStorageSlot is the storage slot used by Diamond proxies (EIP-2535).
const DiamondStorageSlot = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"

// ProxyType represents the type of proxy pattern detected.
type ProxyType string

const (
	ProxyTypeNone        ProxyType = ""
	ProxyTypeERC1967     ProxyType = "ERC1967"
	ProxyTypeTransparent ProxyType = "Transparent"
	ProxyTypeUUPS        ProxyType = "UUPS"
	ProxyTypeBeacon      ProxyType = "Beacon"
	ProxyTypeDiamond     ProxyType = "Diamond"
	ProxyTypeUnknown     ProxyType = "Unknown"
)

// ProxyInfo contains information about detected proxy patterns in bytecode.
type ProxyInfo struct {
	IsProxy            bool      // True if proxy patterns were detected
	ProxyType          ProxyType // The identified proxy type
	ImplementationSlot string    // Storage slot for implementation address
	AdminSlot          string    // Storage slot for admin (if applicable)
	BeaconSlot         string    // Storage slot for beacon (if applicable)
	UpgradeSelectors   []string  // Function selectors that trigger upgrades
}

// DetectProxyPattern analyzes bytecode to detect known upgradeable proxy patterns.
// It looks for ERC-1967 storage slot patterns, DELEGATECALL usage, and upgrade
// function selectors to identify the proxy type.
func DetectProxyPattern(bc *Bytecode) *ProxyInfo {
	info := &ProxyInfo{
		IsProxy:          false,
		ProxyType:        ProxyTypeNone,
		UpgradeSelectors: make([]string, 0),
	}

	if bc == nil || len(bc.Opcodes) == 0 {
		return info
	}

	// Check for DELEGATECALL - required for any proxy pattern
	if !bc.HasOpcode(DELEGATECALL) {
		return info
	}

	// Find ERC-1967 storage slots in the bytecode
	foundSlots := findERC1967Slots(bc)

	// Find upgrade function selectors
	foundSelectors := findUpgradeSelectors(bc)
	info.UpgradeSelectors = foundSelectors

	// Find Diamond-specific patterns
	foundDiamondSelectors := findDiamondSelectors(bc)
	hasDiamondSlot := findDiamondStorageSlot(bc)

	// Determine proxy type based on detected patterns
	hasImplementationSlot := foundSlots["implementation"] != ""
	hasAdminSlot := foundSlots["admin"] != ""
	hasBeaconSlot := foundSlots["beacon"] != ""

	// Store detected slots
	if hasImplementationSlot {
		info.ImplementationSlot = foundSlots["implementation"]
	}
	if hasAdminSlot {
		info.AdminSlot = foundSlots["admin"]
	}
	if hasBeaconSlot {
		info.BeaconSlot = foundSlots["beacon"]
	}

	// Diamond proxy detection (check first as it's most specific)
	if len(foundDiamondSelectors) >= 2 || hasDiamondSlot {
		info.IsProxy = true
		info.ProxyType = ProxyTypeDiamond
		info.UpgradeSelectors = append(info.UpgradeSelectors, foundDiamondSelectors...)
		return info
	}

	// Beacon proxy detection
	if hasBeaconSlot {
		info.IsProxy = true
		info.ProxyType = ProxyTypeBeacon
		return info
	}

	// Transparent proxy detection (has both implementation and admin slots)
	if hasImplementationSlot && hasAdminSlot {
		info.IsProxy = true
		info.ProxyType = ProxyTypeTransparent
		return info
	}

	// UUPS proxy detection (implementation slot but upgrade logic in implementation)
	// UUPS proxies have upgrade selectors in the bytecode
	if hasImplementationSlot && len(foundSelectors) > 0 {
		info.IsProxy = true
		info.ProxyType = ProxyTypeUUPS
		return info
	}

	// Basic ERC1967 proxy (just implementation slot)
	if hasImplementationSlot {
		info.IsProxy = true
		info.ProxyType = ProxyTypeERC1967
		return info
	}

	// Check for DELEGATECALL with SLOAD pattern (generic proxy detection)
	if hasProxyForwardingPattern(bc) {
		info.IsProxy = true
		info.ProxyType = ProxyTypeUnknown
		return info
	}

	return info
}

// findERC1967Slots looks for PUSH32 opcodes that contain ERC-1967 storage slot values.
func findERC1967Slots(bc *Bytecode) map[string]string {
	found := make(map[string]string)

	for i, op := range bc.Opcodes {
		if op.Code != PUSH32 || len(op.Args) != 32 {
			continue
		}

		slotHex := "0x" + strings.ToLower(hex.EncodeToString(op.Args))

		// Check if this is a known ERC-1967 slot
		if slotName, ok := ERC1967Slots[slotHex]; ok {
			// Verify there's an SLOAD following this PUSH32 (within a few opcodes)
			if hasSLOADFollowing(bc.Opcodes, i, 5) {
				found[slotName] = slotHex
			}
		}
	}

	return found
}

// hasSLOADFollowing checks if there's an SLOAD opcode within n opcodes after index.
func hasSLOADFollowing(opcodes []Opcode, index int, n int) bool {
	endIdx := index + n + 1
	if endIdx > len(opcodes) {
		endIdx = len(opcodes)
	}

	for i := index + 1; i < endIdx; i++ {
		if opcodes[i].Code == SLOAD {
			return true
		}
	}
	return false
}

// findUpgradeSelectors looks for known upgrade function selectors in the bytecode.
func findUpgradeSelectors(bc *Bytecode) []string {
	var found []string
	seen := make(map[string]bool)

	for _, op := range bc.Opcodes {
		// Check PUSH4 for function selectors
		if op.Code == PUSH4 && len(op.Args) == 4 {
			selectorHex := "0x" + strings.ToLower(hex.EncodeToString(op.Args))
			if _, ok := UpgradeSelectors[selectorHex]; ok {
				if !seen[selectorHex] {
					seen[selectorHex] = true
					found = append(found, selectorHex)
				}
			}
		}
	}

	return found
}

// findDiamondSelectors looks for Diamond proxy (EIP-2535) function selectors.
func findDiamondSelectors(bc *Bytecode) []string {
	var found []string
	seen := make(map[string]bool)

	for _, op := range bc.Opcodes {
		if op.Code == PUSH4 && len(op.Args) == 4 {
			selectorHex := "0x" + strings.ToLower(hex.EncodeToString(op.Args))
			if _, ok := DiamondSelectors[selectorHex]; ok {
				if !seen[selectorHex] {
					seen[selectorHex] = true
					found = append(found, selectorHex)
				}
			}
		}
	}

	return found
}

// findDiamondStorageSlot checks if the Diamond storage slot is present.
func findDiamondStorageSlot(bc *Bytecode) bool {
	for _, op := range bc.Opcodes {
		if op.Code == PUSH32 && len(op.Args) == 32 {
			slotHex := "0x" + strings.ToLower(hex.EncodeToString(op.Args))
			if slotHex == DiamondStorageSlot {
				return true
			}
		}
	}
	return false
}

// hasProxyForwardingPattern checks for a typical proxy forwarding pattern:
// PUSH32 (storage slot) -> SLOAD -> ... -> DELEGATECALL
func hasProxyForwardingPattern(bc *Bytecode) bool {
	// Look for SLOAD followed by DELEGATECALL pattern
	for i := 0; i < len(bc.Opcodes); i++ {
		if bc.Opcodes[i].Code != SLOAD {
			continue
		}

		// Check if there's a DELEGATECALL after this SLOAD (within reasonable distance)
		for j := i + 1; j < len(bc.Opcodes) && j < i+20; j++ {
			if bc.Opcodes[j].Code == DELEGATECALL {
				// Also verify there's a PUSH32 before the SLOAD (storage slot)
				for k := i - 1; k >= 0 && k >= i-5; k-- {
					if bc.Opcodes[k].Code == PUSH32 {
						return true
					}
				}
			}
		}
	}

	return false
}

// IsUpgradeableProxy returns true if the bytecode represents an upgradeable proxy
// that can have its implementation changed.
func IsUpgradeableProxy(bc *Bytecode) bool {
	info := DetectProxyPattern(bc)
	return info.IsProxy && info.ProxyType != ProxyTypeNone
}

// GetProxyImplementationSlot returns the storage slot for the implementation address
// if the bytecode is a detected proxy pattern, empty string otherwise.
func GetProxyImplementationSlot(bc *Bytecode) string {
	info := DetectProxyPattern(bc)
	return info.ImplementationSlot
}
