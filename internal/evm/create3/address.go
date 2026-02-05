// Package create3 provides utilities for calculating CREATE3 deployment addresses.
//
// CREATE3 allows deploying contracts at deterministic addresses independent of
// the bytecode being deployed. It works by:
// 1. Using CREATE2 to deploy a minimal proxy at a deterministic address
// 2. The proxy then deploys the actual contract using CREATE (with nonce 1)
//
// The final address depends only on the factory address and salt, not the bytecode.
package create3

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ProxyBytecodeHash is the keccak256 hash of the CREATE3 proxy bytecode.
// This is the standard proxy bytecode used by Solmate/Solady CREATE3 implementations.
// Proxy bytecode: 0x67363d3d37363d34f03d5260086018f3
var ProxyBytecodeHash = crypto.Keccak256Hash(common.FromHex("0x67363d3d37363d34f03d5260086018f3"))

// CalculateCREATE3Address calculates the CREATE3 deployment address for a given
// factory contract and salt.
//
// The calculation follows these steps:
// 1. Calculate the CREATE2 address where the proxy will be deployed
// 2. Calculate the CREATE address for the final contract (deployed by proxy with nonce 1)
//
// Parameters:
//   - factory: The address of the CREATE3 factory contract
//   - salt: The 32-byte salt used for deployment
//
// Returns the deterministic address where the contract will be deployed.
func CalculateCREATE3Address(factory common.Address, salt [32]byte) common.Address {
	// Step 1: Calculate CREATE2 address for the proxy
	// CREATE2 address = keccak256(0xff ++ factory ++ salt ++ keccak256(proxy_bytecode))[12:]
	proxyAddress := crypto.CreateAddress2(factory, salt, ProxyBytecodeHash.Bytes())

	// Step 2: Calculate CREATE address (proxy deploys contract with nonce 1)
	// For nonce 1, RLP encoding is: 0xd694{address}01
	finalAddress := crypto.CreateAddress(proxyAddress, 1)

	return finalAddress
}

// CalculateCREATE3AddressFromHex is a convenience wrapper that accepts hex strings.
func CalculateCREATE3AddressFromHex(factory string, saltHex string) (common.Address, error) {
	if !common.IsHexAddress(factory) {
		return common.Address{}, fmt.Errorf("invalid factory address: %s", factory)
	}

	factoryAddr := common.HexToAddress(factory)

	// Remove 0x prefix if present
	saltHex = strings.TrimPrefix(saltHex, "0x")

	// Pad salt to 32 bytes if shorter
	if len(saltHex) < 64 {
		saltHex = strings.Repeat("0", 64-len(saltHex)) + saltHex
	}

	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid salt hex: %w", err)
	}

	if len(saltBytes) != 32 {
		return common.Address{}, fmt.Errorf("salt must be 32 bytes, got %d", len(saltBytes))
	}

	var salt [32]byte
	copy(salt[:], saltBytes)

	return CalculateCREATE3Address(factoryAddr, salt), nil
}

// GeneratedAddress represents a pre-computed CREATE3 address with its salt.
type GeneratedAddress struct {
	Address common.Address `json:"address"`
	Salt    [32]byte       `json:"salt"`
}

// GenerateAddressPoolForOrg generates a batch of CREATE3 addresses using org-scoped salts.
//
// IMPORTANT: This function includes the orgID in the salt computation to ensure
// cross-organization isolation. Even if two orgs use the same factory and salt prefix,
// they will get different addresses.
//
// Parameters:
//   - factory: The address of the CREATE3 factory contract
//   - orgID: The organization ID (included in salt for isolation)
//   - saltPrefix: A prefix for the salt (will be padded and combined with counter)
//   - count: Number of addresses to generate (max 100)
//
// The salt for each address is: keccak256(orgID || saltPrefix || counter)
// This ensures unique, deterministic salts for each address in the pool,
// with guaranteed isolation between organizations.
func GenerateAddressPoolForOrg(factory common.Address, orgID string, saltPrefix []byte, count int) ([]GeneratedAddress, error) {
	if count < 1 || count > 100 {
		return nil, fmt.Errorf("count must be between 1 and 100, got %d", count)
	}

	if orgID == "" {
		return nil, fmt.Errorf("orgID is required for address generation")
	}

	addresses := make([]GeneratedAddress, count)

	for i := 0; i < count; i++ {
		// Generate salt: keccak256(orgID || saltPrefix || counter)
		// Including orgID ensures different orgs get different addresses even with same salt prefix
		counterBytes := big.NewInt(int64(i)).Bytes()
		saltInput := append([]byte(orgID), saltPrefix...)
		saltInput = append(saltInput, counterBytes...)
		saltHash := crypto.Keccak256(saltInput)

		var salt [32]byte
		copy(salt[:], saltHash)

		addresses[i] = GeneratedAddress{
			Address: CalculateCREATE3Address(factory, salt),
			Salt:    salt,
		}
	}

	return addresses, nil
}

// GenerateAddressPool generates a batch of CREATE3 addresses using sequential salts.
// DEPRECATED: Use GenerateAddressPoolForOrg instead to ensure cross-org isolation.
//
// Parameters:
//   - factory: The address of the CREATE3 factory contract
//   - saltPrefix: A prefix for the salt (will be padded and combined with counter)
//   - count: Number of addresses to generate (max 100)
//
// The salt for each address is: keccak256(saltPrefix || counter)
// This ensures unique, deterministic salts for each address in the pool.
func GenerateAddressPool(factory common.Address, saltPrefix []byte, count int) ([]GeneratedAddress, error) {
	if count < 1 || count > 100 {
		return nil, fmt.Errorf("count must be between 1 and 100, got %d", count)
	}

	addresses := make([]GeneratedAddress, count)

	for i := 0; i < count; i++ {
		// Generate salt: keccak256(saltPrefix || counter)
		counterBytes := big.NewInt(int64(i)).Bytes()
		saltInput := append(saltPrefix, counterBytes...)
		saltHash := crypto.Keccak256(saltInput)

		var salt [32]byte
		copy(salt[:], saltHash)

		addresses[i] = GeneratedAddress{
			Address: CalculateCREATE3Address(factory, salt),
			Salt:    salt,
		}
	}

	return addresses, nil
}

// GenerateAddressPoolFromHexForOrg is a convenience wrapper that accepts hex or text strings,
// with org-scoped salt computation for cross-organization isolation.
func GenerateAddressPoolFromHexForOrg(factory string, orgID string, saltPrefixInput string, count int) ([]GeneratedAddress, error) {
	if !common.IsHexAddress(factory) {
		return nil, fmt.Errorf("invalid factory address: %s", factory)
	}

	factoryAddr := common.HexToAddress(factory)
	saltPrefix := parseSaltPrefix(saltPrefixInput)

	return GenerateAddressPoolForOrg(factoryAddr, orgID, saltPrefix, count)
}

// GenerateAddressPoolFromHex is a convenience wrapper that accepts hex or text strings.
// DEPRECATED: Use GenerateAddressPoolFromHexForOrg instead to ensure cross-org isolation.
// If the input starts with 0x and is valid hex, it's decoded as hex.
// Otherwise, it's treated as raw text bytes.
func GenerateAddressPoolFromHex(factory string, saltPrefixInput string, count int) ([]GeneratedAddress, error) {
	if !common.IsHexAddress(factory) {
		return nil, fmt.Errorf("invalid factory address: %s", factory)
	}

	factoryAddr := common.HexToAddress(factory)
	saltPrefix := parseSaltPrefix(saltPrefixInput)

	return GenerateAddressPool(factoryAddr, saltPrefix, count)
}

// parseSaltPrefix parses a salt prefix from hex or text input.
func parseSaltPrefix(saltPrefixInput string) []byte {
	var saltPrefix []byte
	if saltPrefixInput != "" {
		// Check if it looks like hex (starts with 0x)
		if strings.HasPrefix(saltPrefixInput, "0x") {
			hexStr := strings.TrimPrefix(saltPrefixInput, "0x")
			if hexStr != "" {
				decoded, err := hex.DecodeString(hexStr)
				if err != nil {
					// Not valid hex after 0x prefix - treat the whole thing as text
					saltPrefix = []byte(saltPrefixInput)
				} else {
					saltPrefix = decoded
				}
			}
		} else {
			// No 0x prefix - treat as raw text
			saltPrefix = []byte(saltPrefixInput)
		}
	}
	return saltPrefix
}
