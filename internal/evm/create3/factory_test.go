package create3

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestIsTrustedFactoryBytecode(t *testing.T) {
	// Test with empty bytecode
	if result := IsTrustedFactoryBytecode(nil); result != nil {
		t.Error("Expected nil for empty bytecode")
	}

	if result := IsTrustedFactoryBytecode([]byte{}); result != nil {
		t.Error("Expected nil for empty bytecode slice")
	}

	// Test with random bytecode (should not match)
	randomBytecode := []byte{0x60, 0x80, 0x60, 0x40, 0x52}
	if result := IsTrustedFactoryBytecode(randomBytecode); result != nil {
		t.Error("Expected nil for random bytecode")
	}
}

func TestIsTrustedFactoryHash(t *testing.T) {
	// Test with non-matching hash
	if result := IsTrustedFactoryHash("0x0000000000000000000000000000000000000000000000000000000000000000"); result != nil {
		t.Error("Expected nil for non-matching hash")
	}

	// Test with our simple factory hash (should match since it's auto-added)
	if result := IsTrustedFactoryHash(SimpleCreate3FactoryHash); result == nil {
		t.Error("Expected match for SimpleCreate3FactoryHash")
	} else if result.Name != "Privacy Proxy Simple CREATE3 Factory" {
		t.Errorf("Expected 'Privacy Proxy Simple CREATE3 Factory', got '%s'", result.Name)
	}
}

func TestAddTrustedFactory(t *testing.T) {
	// Create a unique test hash
	testBytecode := []byte("test-factory-bytecode-12345")
	testHash := crypto.Keccak256Hash(testBytecode).Hex()

	// Initially should not match
	if result := IsTrustedFactoryHash(testHash); result != nil {
		t.Error("Expected nil before adding factory")
	}

	// Add the factory
	AddTrustedFactory(TrustedFactory{
		Name:         "Test Factory",
		BytecodeHash: testHash,
		Source:       "test",
	})

	// Now should match
	result := IsTrustedFactoryHash(testHash)
	if result == nil {
		t.Error("Expected match after adding factory")
	} else if result.Name != "Test Factory" {
		t.Errorf("Expected 'Test Factory', got '%s'", result.Name)
	}

	// Should also match by bytecode
	result2 := IsTrustedFactoryBytecode(testBytecode)
	if result2 == nil {
		t.Error("Expected bytecode match after adding factory")
	}
}

func TestGetTrustedFactories(t *testing.T) {
	factories := GetTrustedFactories()
	if len(factories) == 0 {
		t.Error("Expected at least one trusted factory (SimpleCreate3Factory)")
	}

	// Check that our simple factory is in the list
	found := false
	for _, f := range factories {
		if f.Name == "Privacy Proxy Simple CREATE3 Factory" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find Privacy Proxy Simple CREATE3 Factory in trusted factories")
	}
}

func TestHashNormalization(t *testing.T) {
	// Test that hashes are normalized correctly
	testBytecode := []byte("test-normalization")
	hash := crypto.Keccak256Hash(testBytecode).Hex()

	AddTrustedFactory(TrustedFactory{
		Name:         "Normalization Test",
		BytecodeHash: hash, // With 0x prefix
		Source:       "test",
	})

	// Should match with 0x prefix
	if IsTrustedFactoryHash(hash) == nil {
		t.Error("Expected match with 0x prefix")
	}

	// Should match without 0x prefix
	if IsTrustedFactoryHash(hash[2:]) == nil {
		t.Error("Expected match without 0x prefix")
	}

	// Should match with uppercase
	if IsTrustedFactoryHash("0x" + hash[2:]) == nil {
		t.Error("Expected match with mixed case")
	}
}

func TestSimpleCreate3FactoryHashComputed(t *testing.T) {
	// Verify the simple factory hash is properly computed
	if SimpleCreate3FactoryHash == "" {
		t.Error("SimpleCreate3FactoryHash should not be empty")
	}

	if len(SimpleCreate3FactoryHash) != 66 { // "0x" + 64 hex chars
		t.Errorf("Expected 66 character hash, got %d", len(SimpleCreate3FactoryHash))
	}

	if SimpleCreate3FactoryHash[:2] != "0x" {
		t.Error("Expected hash to start with 0x")
	}
}

func TestProxyBytecodeHash(t *testing.T) {
	// Verify the proxy bytecode hash matches expected
	// The proxy bytecode should be: 0x67363d3d37363d34f03d5260086018f3
	expectedProxyBytecode := common.FromHex("0x67363d3d37363d34f03d5260086018f3")
	computedHash := crypto.Keccak256Hash(expectedProxyBytecode)

	if computedHash != ProxyBytecodeHash {
		t.Errorf("ProxyBytecodeHash mismatch.\nExpected: %s\nGot: %s", ProxyBytecodeHash.Hex(), computedHash.Hex())
	}
}
