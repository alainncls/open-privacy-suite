package rbac

import (
	"strings"

	"privacy-proxy/internal/evm/bytecode"
)

// WellKnownStorageSlots is the set of storage slots that read-claim users may
// access via eth_getStorageAt. These are infrastructure metadata slots defined
// by EIP-1967 (proxy implementation/admin/beacon) and EIP-2535 (Diamond storage).
// They contain only contract addresses, not business data.
//
// This allowlist is intentionally hardcoded — new standards require a code change
// with security review. Do NOT make this configurable.
var WellKnownStorageSlots map[string]bool

func init() {
	WellKnownStorageSlots = make(map[string]bool, len(bytecode.ERC1967Slots)+1)
	for slot := range bytecode.ERC1967Slots {
		WellKnownStorageSlots[strings.ToLower(slot)] = true
	}
	WellKnownStorageSlots[strings.ToLower(bytecode.DiamondStorageSlot)] = true
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
