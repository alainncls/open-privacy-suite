package rbac

import (
	"strings"
)

// erc1967Slots is the set of standard EIP-1967 storage slot hashes
// (implementation, admin, beacon) used by upgradeable proxy contracts
// to keep proxy metadata in predictable locations. Inlined here
// because they're consumed only by the eth_getStorageAt allowlist
// below; the historical home in internal/evm/bytecode/proxy.go was
// deleted alongside the dead deploy-time bytecode analyzer.
var erc1967Slots = []string{
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", // implementation
	"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", // admin
	"0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", // beacon
}

// diamondStorageSlot is the EIP-2535 Diamond storage slot.
const diamondStorageSlot = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"

// WellKnownStorageSlots is the set of storage slots that read-claim users may
// access via eth_getStorageAt. These are infrastructure metadata slots defined
// by EIP-1967 (proxy implementation/admin/beacon) and EIP-2535 (Diamond storage).
// They contain only contract addresses, not business data.
//
// This allowlist is intentionally hardcoded — new standards require a code change
// with security review. Do NOT make this configurable.
var WellKnownStorageSlots map[string]bool

func init() {
	WellKnownStorageSlots = make(map[string]bool, len(erc1967Slots)+1)
	for _, slot := range erc1967Slots {
		WellKnownStorageSlots[strings.ToLower(slot)] = true
	}
	WellKnownStorageSlots[strings.ToLower(diamondStorageSlot)] = true
}

// IsWellKnownStorageSlot checks if a storage slot is in the infrastructure allowlist.
// The slot should be a hex string (with or without 0x prefix).
// Returns false for empty/invalid slots (fail-closed).
func IsWellKnownStorageSlot(slot string) bool {
	if slot == "" {
		return false
	}
	slot = strings.ToLower(strings.TrimSpace(slot))
	// Normalize: ensure 0x prefix for map lookup
	if !strings.HasPrefix(slot, "0x") {
		slot = "0x" + slot
	}
	// Pad to 66 chars (0x + 64 hex digits) if needed — some clients send short-form
	// but our constants are full 32-byte hex
	return WellKnownStorageSlots[slot]
}

// extractStorageSlot extracts the storage slot (params[1]) from eth_getStorageAt params.
// Returns empty string if params are missing or malformed (fail-closed: will be denied).
func extractStorageSlot(params []any) string {
	if len(params) < 2 {
		return ""
	}
	slot, ok := params[1].(string)
	if !ok {
		return ""
	}
	return slot
}
