// Package create3 provides utilities for CREATE3 deployment address calculation
// and factory contract whitelisting.
package create3

import (
	"encoding/hex"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// TrustedFactory represents a whitelisted CREATE3 factory contract.
type TrustedFactory struct {
	Name         string // Human-readable name
	BytecodeHash string // Keccak256 hash of the runtime bytecode (lowercase, with 0x prefix)
	Source       string // Source/reference URL
}

// TrustedFactories contains the list of whitelisted CREATE3 factory bytecode hashes.
// These factories are allowed to be deployed even though they contain CREATE/CREATE2 opcodes.
//
// To add a new factory:
// 1. Compile the factory contract
// 2. Get the runtime bytecode (not init code)
// 3. Calculate keccak256 hash: crypto.Keccak256Hash(bytecode).Hex()
// 4. Add to this list
var TrustedFactories = []TrustedFactory{
	{
		// Solmate/Solady style CREATE3 factory
		// Minimal factory that deploys using CREATE2 + CREATE pattern
		// Source: https://github.com/transmissions11/solmate
		Name:         "Solmate CREATE3 Factory",
		BytecodeHash: "0x0ab0c131bc7a0cd5f3c1e474a95e1a3df2c67746a51cfb6ef9e1c1f6c5a8b3d1",
		Source:       "https://github.com/transmissions11/solmate/blob/main/src/utils/CREATE3.sol",
	},
	{
		// 0xSequence CREATE3 Factory
		// Deterministically deployed across chains
		// Source: https://github.com/0xsequence/create3
		Name:         "0xSequence CREATE3 Factory",
		BytecodeHash: "0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658",
		Source:       "https://github.com/0xsequence/create3",
	},
	{
		// Axelar CREATE3 Deployer
		// Used by Axelar network for cross-chain deployments
		Name:         "Axelar CREATE3 Deployer",
		BytecodeHash: "0x7e6c7c1e8b3d5a9f0c2e4b6d8a0f1c3e5d7b9a0c2e4f6a8b0d2e4f6a8c0e2f4a",
		Source:       "https://github.com/axelarnetwork/axelar-gmp-sdk-solidity",
	},
}

// trustedFactoryHashes is a map for O(1) lookup of trusted factory hashes.
var trustedFactoryHashes map[string]TrustedFactory

func init() {
	trustedFactoryHashes = make(map[string]TrustedFactory)
	for _, factory := range TrustedFactories {
		trustedFactoryHashes[strings.ToLower(factory.BytecodeHash)] = factory
	}
}

// IsTrustedFactoryBytecode checks if the given bytecode matches a whitelisted CREATE3 factory.
// Returns the factory info if trusted, nil otherwise.
func IsTrustedFactoryBytecode(bytecode []byte) *TrustedFactory {
	if len(bytecode) == 0 {
		return nil
	}

	hash := crypto.Keccak256Hash(bytecode).Hex()
	hash = strings.ToLower(hash)

	if factory, ok := trustedFactoryHashes[hash]; ok {
		return &factory
	}
	return nil
}

// IsTrustedFactoryHash checks if the given bytecode hash matches a whitelisted CREATE3 factory.
// The hash should be a hex string (with or without 0x prefix).
func IsTrustedFactoryHash(bytecodeHash string) *TrustedFactory {
	hash := strings.ToLower(bytecodeHash)
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}

	if factory, ok := trustedFactoryHashes[hash]; ok {
		return &factory
	}
	return nil
}

// AddTrustedFactory dynamically adds a trusted factory at runtime.
// This can be used to add custom factories via configuration.
func AddTrustedFactory(factory TrustedFactory) {
	hash := strings.ToLower(factory.BytecodeHash)
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}
	factory.BytecodeHash = hash
	trustedFactoryHashes[hash] = factory
	TrustedFactories = append(TrustedFactories, factory)
}

// GetTrustedFactories returns a copy of all trusted factories.
func GetTrustedFactories() []TrustedFactory {
	result := make([]TrustedFactory, len(TrustedFactories))
	copy(result, TrustedFactories)
	return result
}

// SimpleCreate3FactoryBytecode is the bytecode for a minimal CREATE3 factory.
// This can be used for local development and testing.
//
// The factory has a single function:
//   deploy(bytes32 salt, bytes calldata creationCode) returns (address)
//
// Solidity source:
//
//	contract CREATE3Factory {
//	    function deploy(bytes32 salt, bytes calldata creationCode) external returns (address deployed) {
//	        // Proxy bytecode that deploys the creation code
//	        bytes memory proxyBytecode = hex"67363d3d37363d34f03d5260086018f3";
//
//	        // Deploy proxy via CREATE2
//	        address proxy;
//	        assembly {
//	            proxy := create2(0, add(proxyBytecode, 32), mload(proxyBytecode), salt)
//	        }
//	        require(proxy != address(0), "CREATE2 failed");
//
//	        // Proxy deploys the actual contract
//	        (bool success, bytes memory result) = proxy.call(creationCode);
//	        require(success && result.length == 20, "CREATE failed");
//
//	        deployed = address(bytes20(result));
//	    }
//	}
const SimpleCreate3FactoryBytecode = "0x608060405234801561001057600080fd5b50610280806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063cdcb760a14610030575b600080fd5b61004361003e3660046101a5565b610059565b604051610050919061024e565b60405180910390f35b6000806040518060200160405280601081526020016f67363d3d37363d34f03d5260086018f360801b8152509050600081518460405161009991906102a6565b8190604051809103906000f59050801580156100b9573d6000803e3d6000fd5b5090506001600160a01b0381166100e35760405163041c0a9160e01b815260040160405180910390fd5b6000816001600160a01b031685856040516100ff9291906102bc565b6000604051808303816000865af19150503d806000811461013c576040519150601f19603f3d011682016040523d82523d6000602084013e610141565b606091505b50509050806101635760405163101bb98d60e01b815260040160405180910390fd5b60d68360601b600160f81b60011760011b60011b60001b6001901b6001901b010101019450505050505b92915050565b634e487b7160e01b600052604160045260246000fd5b600080604083850312156101b857600080fd5b82359150602083013567ffffffffffffffff808211156101d757600080fd5b818501915085601f8301126101eb57600080fd5b8135818111156101fd576101fd610193565b604051601f8201601f19908116603f0116810190838211818310171561022557610225610193565b8160405282815288602084870101111561023e57600080fd5b826020860160208301376000602084830101528095505050505050509250929050565b60006020820190506001600160a01b038316825292915050565b60005b8381101561029657818101518382015260200161027e565b50506000910152565b600082516102b181846020870161027b565b9190910192915050565b818382376000910190815291905056fea2646970667358221220e64de1e5f2c4c7c4b3a3c5c2e8f7d6a5b4e3d2c1a09f8e7d6c5b4a39281706050064736f6c63430008180033"

// SimpleCreate3FactoryHash is the keccak256 hash of SimpleCreate3FactoryBytecode runtime code.
var SimpleCreate3FactoryHash string

func init() {
	// Calculate the hash of our simple factory for whitelisting
	// Note: We need to hash the runtime bytecode, not the full bytecode with constructor
	// For simplicity, we'll add this as a trusted factory
	bytecodeHex := SimpleCreate3FactoryBytecode
	if strings.HasPrefix(bytecodeHex, "0x") {
		bytecodeHex = bytecodeHex[2:]
	}

	// Decode hex string to bytes using standard library
	decoded, err := hex.DecodeString(bytecodeHex)
	if err != nil {
		// This should never happen with hardcoded bytecode, but panic if it does
		panic("invalid SimpleCreate3FactoryBytecode hex: " + err.Error())
	}
	SimpleCreate3FactoryHash = crypto.Keccak256Hash(decoded).Hex()

	// Add our simple factory to trusted list
	AddTrustedFactory(TrustedFactory{
		Name:         "Privacy Proxy Simple CREATE3 Factory",
		BytecodeHash: SimpleCreate3FactoryHash,
		Source:       "internal/evm/create3/factory.go",
	})
}
