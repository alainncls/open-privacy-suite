package rbac

import (
	"testing"
)

func TestExpandClaims(t *testing.T) {
	tests := []struct {
		name     string
		input    []Claim
		expected []Claim
	}{
		{
			name:     "admin expands to all claims",
			input:    []Claim{ClaimAdmin},
			expected: []Claim{ClaimAdmin, ClaimDeploy, ClaimRead, ClaimUpgrade, ClaimWrite},
		},
		{
			name:     "deploy expands to read and write",
			input:    []Claim{ClaimDeploy},
			expected: []Claim{ClaimDeploy, ClaimRead, ClaimWrite},
		},
		{
			name:     "upgrade expands to read and write",
			input:    []Claim{ClaimUpgrade},
			expected: []Claim{ClaimRead, ClaimUpgrade, ClaimWrite},
		},
		{
			name:     "deploy and upgrade deduplicate read and write",
			input:    []Claim{ClaimDeploy, ClaimUpgrade},
			expected: []Claim{ClaimDeploy, ClaimRead, ClaimUpgrade, ClaimWrite},
		},
		{
			name:     "read alone stays as read",
			input:    []Claim{ClaimRead},
			expected: []Claim{ClaimRead},
		},
		{
			name:     "write alone stays as write",
			input:    []Claim{ClaimWrite},
			expected: []Claim{ClaimWrite},
		},
		{
			name:     "empty input returns empty",
			input:    []Claim{},
			expected: []Claim{},
		},
		{
			name:     "already expanded input is idempotent",
			input:    []Claim{ClaimAdmin, ClaimRead, ClaimWrite, ClaimDeploy, ClaimUpgrade},
			expected: []Claim{ClaimAdmin, ClaimDeploy, ClaimRead, ClaimUpgrade, ClaimWrite},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandClaims(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
			for i, claim := range result {
				if claim != tt.expected[i] {
					t.Fatalf("expected %v at index %d, got %v (full result: %v)", tt.expected[i], i, claim, result)
				}
			}
		})
	}
}
