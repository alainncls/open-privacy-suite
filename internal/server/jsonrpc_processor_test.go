package server

import "testing"

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
