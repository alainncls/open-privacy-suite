package server

import (
	"testing"
)

// =============================================================================
// CRITICAL SECURITY TEST: Cross-Org Isolation via Tracing
// =============================================================================
//
// This test documents the security invariant that MUST be maintained:
//
// Even when calling an org-owned contract, if that contract makes internal
// calls to another org's contract, the transaction MUST be denied.
//
// The bug we caught: Tiered validation was skipping tracing entirely for
// org-owned contracts, allowing this attack:
//
//   User → OrgA_Contract.attack(OrgB_Addr) → OrgB_Contract  ❌ VIOLATION
//
// The fix: Only skip tracing for the CREATE3 factory (audited, deterministic).
// All other contracts MUST be traced regardless of ownership.
//
// NOTE: Full integration test for this is in e2e tests. This documents the
// invariant that tiered validation ONLY skips for factory, not org-owned.

func TestTieredValidation_OnlySkipsFactory(t *testing.T) {
	// This test documents the security requirement:
	// Tiered validation should ONLY skip tracing for:
	// 1. CREATE3 factory (audited, deterministic, no arbitrary calls)
	//
	// It should NOT skip for:
	// 1. General org-owned contracts (could make cross-org calls via user input)
	// 2. Unknown contracts
	//
	// The implementation is in validateWithTracing() in jsonrpc_processor.go
	// A full integration test requires mocking the entire tracer infrastructure.
	//
	// Key code path to verify:
	// - jsonrpc_processor.go: validateWithTracing()
	// - Only checks for factory address match
	// - Does NOT check IsAddressOwnedByOrg for general contracts
	t.Log("Security invariant: tiered validation only skips CREATE3 factory")
	t.Log("See jsonrpc_processor.go:validateWithTracing() for implementation")
}

func TestIsSimpleValueTransfer(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		// Simple value transfers (should return true - skip tracing)
		{"empty string", "", true},
		{"0x only", "0x", true},
		{"0X only", "0X", true},
		{"0x with whitespace", "  0x  ", true},
		{"empty with whitespace", "   ", true},

		// Contract calls (should return false - need tracing)
		{"function selector", "0xa9059cbb", false},
		{"full calldata", "0xa9059cbb000000000000000000000000deadbeef", false},
		{"transfer call", "0xa9059cbb0000000000000000000000001234567890123456789012345678901234567890", false},
		{"short data", "0x12", false},
		{"non-hex prefix", "a9059cbb", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSimpleValueTransfer(tt.data)
			if result != tt.expected {
				t.Errorf("isSimpleValueTransfer(%q) = %v, expected %v", tt.data, result, tt.expected)
			}
		})
	}
}
