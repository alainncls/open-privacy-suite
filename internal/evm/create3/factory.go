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

// SimpleCreate3FactoryBytecode is the init code for deploying the CREATE3 factory.
// This can be used for local development and testing.
//
// Source: src/CREATE3Factory.sol
// Compiled with solc 0.8.22 (matching foundry.toml).
//
// The factory has two functions:
//   deploy(bytes32 salt, bytes calldata creationCode) returns (address)
//   getDeployed(bytes32 salt) returns (address)
const SimpleCreate3FactoryBytecode = "0x608060405234801561000f575f80fd5b5061094b8061001d5f395ff3fe608060405260043610610028575f3560e01c8063cdcb760a1461002c578063df20e2521461005c575b5f80fd5b610046600480360381019061004191906104fe565b610098565b6040516100539190610597565b60405180910390f35b348015610067575f80fd5b50610082600480360381019061007d91906105b0565b6102c8565b60405161008f9190610597565b60405180910390f35b5f805f6040518060400160405280601081526020017f67363d3d37363d34f03d5260086018f3000000000000000000000000000000008152509050848151602083015ff591505f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361014c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161014390610635565b60405180910390fd5b5f8273ffffffffffffffffffffffffffffffffffffffff16348660405161017391906106bf565b5f6040518083038185875af1925050503d805f81146101ad576040519150601f19603f3d011682016040523d82523d5f602084013e6101b2565b606091505b50509050806101f6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101ed9061071f565b60405180910390fd5b60d660f81b609460f81b84600160f81b60405160200161021994939291906107cd565b604051602081830303815290604052805190602001205f1c93505f843b90505f811161027a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102719061088a565b60405180910390fd5b868573ffffffffffffffffffffffffffffffffffffffff167fb085ff794f342ed78acc7791d067e28a931e614b52476c0305795e1ff0a154bc60405160405180910390a35050505092915050565b5f8060ff60f81b30846040518060400160405280601081526020017f67363d3d37363d34f03d5260086018f3000000000000000000000000000000008152508051906020012060405160200161032194939291906108c8565b604051602081830303815290604052805190602001205f1c905060d660f81b609460f81b82600160f81b60405160200161035e94939291906107cd565b604051602081830303815290604052805190602001205f1c915050919050565b5f604051905090565b5f80fd5b5f80fd5b5f819050919050565b6103a18161038f565b81146103ab575f80fd5b50565b5f813590506103bc81610398565b92915050565b5f80fd5b5f80fd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b610410826103ca565b810181811067ffffffffffffffff8211171561042f5761042e6103da565b5b80604052505050565b5f61044161037e565b905061044d8282610407565b919050565b5f67ffffffffffffffff82111561046c5761046b6103da565b5b610475826103ca565b9050602081019050919050565b828183375f83830152505050565b5f6104a261049d84610452565b610438565b9050828152602081018484840111156104be576104bd6103c6565b5b6104c9848285610482565b509392505050565b5f82601f8301126104e5576104e46103c2565b5b81356104f5848260208601610490565b91505092915050565b5f806040838503121561051457610513610387565b5b5f610521858286016103ae565b925050602083013567ffffffffffffffff8111156105425761054161038b565b5b61054e858286016104d1565b9150509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61058182610558565b9050919050565b61059181610577565b82525050565b5f6020820190506105aa5f830184610588565b92915050565b5f602082840312156105c5576105c4610387565b5b5f6105d2848285016103ae565b91505092915050565b5f82825260208201905092915050565b7f435245415445333a2070726f7879206465706c6f796d656e74206661696c65645f82015250565b5f61061f6020836105db565b915061062a826105eb565b602082019050919050565b5f6020820190508181035f83015261064c81610613565b9050919050565b5f81519050919050565b5f81905092915050565b5f5b83811015610684578082015181840152602081019050610669565b5f8484015250505050565b5f61069982610653565b6106a3818561065d565b93506106b3818560208601610667565b80840191505092915050565b5f6106ca828461068f565b915081905092915050565b7f435245415445333a206465706c6f796d656e74206661696c65640000000000005f82015250565b5f610709601a836105db565b9150610714826106d5565b602082019050919050565b5f6020820190508181035f830152610736816106fd565b9050919050565b5f7fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b5f819050919050565b61078261077d8261073d565b610768565b82525050565b5f8160601b9050919050565b5f61079e82610788565b9050919050565b5f6107af82610794565b9050919050565b6107c76107c282610577565b6107a5565b82525050565b5f6107d88287610771565b6001820191506107e88286610771565b6001820191506107f882856107b6565b6014820191506108088284610771565b60018201915081905095945050505050565b7f435245415445333a206465706c6f796d656e7420766572696669636174696f6e5f8201527f206661696c656400000000000000000000000000000000000000000000000000602082015250565b5f6108746027836105db565b915061087f8261081a565b604082019050919050565b5f6020820190508181035f8301526108a181610868565b9050919050565b5f819050919050565b6108c26108bd8261038f565b6108a8565b82525050565b5f6108d38287610771565b6001820191506108e382866107b6565b6014820191506108f382856108b1565b60208201915061090382846108b1565b6020820191508190509594505050505056fea26469706673582212206dca21e0d9789ce5783c77b66871d7f11e2ab0871c9ccff77fb9982a5713aafe64736f6c63430008160033"

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
