package create3

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCalculateCREATE3Address(t *testing.T) {
	// Test case from a known CREATE3 deployment
	// Factory: 0x4e59b44847b379578588920cA78FbF26c0B4956C (common CREATE2 deployer)
	// Salt: 0x0000000000000000000000000000000000000000000000000000000000000001
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	salt := [32]byte{}
	salt[31] = 1

	addr := CalculateCREATE3Address(factory, salt)

	// The address should be deterministic
	if addr == (common.Address{}) {
		t.Error("expected non-zero address")
	}

	// Verify it's a valid Ethereum address (20 bytes, starts with 0x)
	if len(addr.Bytes()) != 20 {
		t.Errorf("expected 20 byte address, got %d bytes", len(addr.Bytes()))
	}

	// Calculate again with same inputs - should be identical
	addr2 := CalculateCREATE3Address(factory, salt)
	if addr != addr2 {
		t.Error("CREATE3 address calculation is not deterministic")
	}
}

func TestCalculateCREATE3AddressFromHex(t *testing.T) {
	tests := []struct {
		name       string
		factory    string
		salt       string
		wantErr    bool
		errContain string
	}{
		{
			name:    "valid inputs",
			factory: "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			salt:    "0x0000000000000000000000000000000000000000000000000000000000000001",
			wantErr: false,
		},
		{
			name:    "valid inputs without 0x prefix",
			factory: "4e59b44847b379578588920cA78FbF26c0B4956C",
			salt:    "0000000000000000000000000000000000000000000000000000000000000001",
			wantErr: false,
		},
		{
			name:    "short salt (will be padded)",
			factory: "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			salt:    "0x01",
			wantErr: false,
		},
		{
			name:       "invalid factory address",
			factory:    "not-an-address",
			salt:       "0x01",
			wantErr:    true,
			errContain: "invalid factory address",
		},
		{
			name:       "invalid salt hex",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			salt:       "0xZZ",
			wantErr:    true,
			errContain: "invalid salt hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := CalculateCREATE3AddressFromHex(tt.factory, tt.salt)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContain)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if addr == (common.Address{}) {
				t.Error("expected non-zero address")
			}
		})
	}
}

func TestGenerateAddressPool(t *testing.T) {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	prefix := []byte("test-prefix")

	// Generate 10 addresses
	addresses, err := GenerateAddressPool(factory, prefix, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addresses) != 10 {
		t.Errorf("expected 10 addresses, got %d", len(addresses))
	}

	// All addresses should be unique
	seen := make(map[common.Address]bool)
	for i, ga := range addresses {
		if seen[ga.Address] {
			t.Errorf("duplicate address at index %d: %s", i, ga.Address.Hex())
		}
		seen[ga.Address] = true

		// Salt should not be empty
		if ga.Salt == [32]byte{} {
			t.Errorf("empty salt at index %d", i)
		}
	}

	// Generate again with same inputs - should be identical
	addresses2, err := GenerateAddressPool(factory, prefix, 10)
	if err != nil {
		t.Fatalf("unexpected error on second generation: %v", err)
	}

	for i := range addresses {
		if addresses[i].Address != addresses2[i].Address {
			t.Errorf("address mismatch at index %d: got %s, want %s",
				i, addresses2[i].Address.Hex(), addresses[i].Address.Hex())
		}
		if addresses[i].Salt != addresses2[i].Salt {
			t.Errorf("salt mismatch at index %d", i)
		}
	}
}

func TestGenerateAddressPool_Limits(t *testing.T) {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	prefix := []byte("test")

	// Test count limits
	_, err := GenerateAddressPool(factory, prefix, 0)
	if err == nil {
		t.Error("expected error for count 0")
	}

	_, err = GenerateAddressPool(factory, prefix, 101)
	if err == nil {
		t.Error("expected error for count > 100")
	}

	// Valid boundary
	_, err = GenerateAddressPool(factory, prefix, 1)
	if err != nil {
		t.Errorf("unexpected error for count 1: %v", err)
	}

	_, err = GenerateAddressPool(factory, prefix, 100)
	if err != nil {
		t.Errorf("unexpected error for count 100: %v", err)
	}
}

func TestGenerateAddressPoolFromHex(t *testing.T) {
	tests := []struct {
		name       string
		factory    string
		saltPrefix string
		count      int
		wantErr    bool
	}{
		{
			name:       "hex salt prefix with 0x",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			saltPrefix: "0xdeadbeef",
			count:      5,
		},
		{
			name:       "text salt prefix",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			saltPrefix: "myapp-v1",
			count:      5,
		},
		{
			name:       "text salt prefix with odd length",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			saltPrefix: "myapp",
			count:      5,
		},
		{
			name:       "text with 0x prefix that is not valid hex",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			saltPrefix: "0xmyapp-v1",
			count:      5,
		},
		{
			name:       "empty salt prefix",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			saltPrefix: "",
			count:      5,
		},
		{
			name:       "just 0x prefix",
			factory:    "0x4e59b44847b379578588920cA78FbF26c0B4956C",
			saltPrefix: "0x",
			count:      5,
		},
		{
			name:       "invalid factory",
			factory:    "not-an-address",
			saltPrefix: "test",
			count:      5,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addresses, err := GenerateAddressPoolFromHex(tt.factory, tt.saltPrefix, tt.count)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(addresses) != tt.count {
				t.Errorf("expected %d addresses, got %d", tt.count, len(addresses))
			}

			// Verify all addresses are valid and unique
			seen := make(map[common.Address]bool)
			for i, ga := range addresses {
				if ga.Address == (common.Address{}) {
					t.Errorf("zero address at index %d", i)
				}
				if seen[ga.Address] {
					t.Errorf("duplicate address at index %d", i)
				}
				seen[ga.Address] = true
			}
		})
	}
}

func TestCalculateCREATE3Address_DifferentSalts(t *testing.T) {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")

	salt1 := [32]byte{}
	salt1[31] = 1

	salt2 := [32]byte{}
	salt2[31] = 2

	addr1 := CalculateCREATE3Address(factory, salt1)
	addr2 := CalculateCREATE3Address(factory, salt2)

	if addr1 == addr2 {
		t.Error("different salts should produce different addresses")
	}
}

func TestCalculateCREATE3Address_DifferentFactories(t *testing.T) {
	factory1 := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	factory2 := common.HexToAddress("0x1111111111111111111111111111111111111111")

	salt := [32]byte{}
	salt[31] = 1

	addr1 := CalculateCREATE3Address(factory1, salt)
	addr2 := CalculateCREATE3Address(factory2, salt)

	if addr1 == addr2 {
		t.Error("different factories should produce different addresses")
	}
}

// Benchmark for address generation
func BenchmarkCalculateCREATE3Address(b *testing.B) {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	salt := [32]byte{}
	salt[31] = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateCREATE3Address(factory, salt)
	}
}

func BenchmarkGenerateAddressPool(b *testing.B) {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	prefix := []byte("benchmark-prefix")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateAddressPool(factory, prefix, 100)
	}
}

// Example demonstrating usage
func ExampleCalculateCREATE3Address() {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	salt := [32]byte{}
	salt[31] = 1

	addr := CalculateCREATE3Address(factory, salt)
	_ = addr.Hex() // Returns the address as a hex string
}

func ExampleGenerateAddressPool() {
	factory := common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")
	prefix := []byte("my-app-v1")

	addresses, _ := GenerateAddressPool(factory, prefix, 10)
	for _, ga := range addresses {
		_ = ga.Address.Hex()              // The deployment address
		_ = hex.EncodeToString(ga.Salt[:]) // The salt to use
	}
}
