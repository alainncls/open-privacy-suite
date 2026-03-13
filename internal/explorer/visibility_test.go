package explorer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGeneratePseudonym(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected string
	}{
		{
			name:     "all zeros (0x prefix)",
			address:  "0x0000000000000000000000000000000000000000",
			expected: "Address-AAAA",
		},
		{
			name:     "all as (hex a=10=K)",
			address:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: "Address-KKKK",
		},
		{
			name:     "all fs (hex f=15=P)",
			address:  "0xffffffffffffffffffffffffffffffffffffffff",
			expected: "Address-PPPP",
		},
		{
			name:     "mixed hex digits",
			address:  "0x1234567890abcdef1234567890abcdef12345678",
			// 1->B, 2->C, 3->D, 4->E
			expected: "Address-BCDE",
		},
		{
			name:     "without 0x prefix",
			address:  "abcd000000000000000000000000000000000000",
			// a->K, b->L, c->M, d->N
			expected: "Address-KLMN",
		},
		{
			name:     "uppercase address",
			address:  "0xABCDEF0000000000000000000000000000000000",
			// a->K, b->L, c->M, d->N
			expected: "Address-KLMN",
		},
		{
			name:     "too short",
			address:  "0x12",
			expected: "Address-Unknown",
		},
		{
			name:     "empty string",
			address:  "",
			expected: "Address-Unknown",
		},
		{
			name:     "invalid hex char",
			address:  "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
			expected: "Address-Unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GeneratePseudonym(tc.address)
			if got != tc.expected {
				t.Errorf("GeneratePseudonym(%q) = %q, want %q", tc.address, got, tc.expected)
			}
		})
	}
}

func TestGeneratePseudonym_Deterministic(t *testing.T) {
	addr := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	first := GeneratePseudonym(addr)
	for i := 0; i < 10; i++ {
		if got := GeneratePseudonym(addr); got != first {
			t.Errorf("not deterministic: got %q on iteration %d, want %q", got, i, first)
		}
	}
}

func TestGeneratePseudonym_StartsWithAddressPrefix(t *testing.T) {
	addr := "0x1234567890abcdef1234567890abcdef12345678"
	result := GeneratePseudonym(addr)
	if !strings.HasPrefix(result, "Address-") {
		t.Errorf("pseudonym should start with 'Address-', got %q", result)
	}
}

func TestGeneratePseudonym_DifferentAddressesDifferentPseudonyms(t *testing.T) {
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	p1 := GeneratePseudonym(addr1)
	p2 := GeneratePseudonym(addr2)
	if p1 == p2 {
		t.Errorf("different addresses should produce different pseudonyms: both give %q", p1)
	}
}

func TestGenerateAddressID_Deterministic(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	grantID := "grant-123"
	first := GenerateAddressID(addr, grantID)
	for i := 0; i < 5; i++ {
		if got := GenerateAddressID(addr, grantID); got != first {
			t.Errorf("not deterministic: got %q on iteration %d", got, i)
		}
	}
}

func TestGenerateAddressID_DifferentInputsDifferentIDs(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	id1 := GenerateAddressID(addr, "grant-1")
	id2 := GenerateAddressID(addr, "grant-2")
	if id1 == id2 {
		t.Errorf("different grant IDs should produce different address IDs")
	}

	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	id3 := GenerateAddressID(addr2, "grant-1")
	if id1 == id3 {
		t.Errorf("different addresses should produce different address IDs")
	}
}

func TestGenerateAddressID_Length(t *testing.T) {
	id := GenerateAddressID("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "grant-1")
	if len(id) != 16 {
		t.Errorf("expected 16 hex chars, got %d: %q", len(id), id)
	}
}

// TestJSONString_MarshalJSON covers the MarshalJSON method on types.go.
func TestJSONString_MarshalJSON(t *testing.T) {
	type payload struct {
		Value JSONString `json:"value"`
	}
	p := payload{Value: "0x1234"}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if got != `{"value":"0x1234"}` {
		t.Errorf("unexpected JSON: %s", got)
	}
}

func TestGenerateAddressID_CaseInsensitive(t *testing.T) {
	lower := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	upper := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	id1 := GenerateAddressID(lower, "grant")
	id2 := GenerateAddressID(upper, "grant")
	if id1 != id2 {
		t.Errorf("address IDs should be case-insensitive: %q vs %q", id1, id2)
	}
}
