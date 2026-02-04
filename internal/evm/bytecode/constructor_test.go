package bytecode

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractConstructorArgs_NoABI(t *testing.T) {
	// ABI is required
	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, "")
	assert.Error(t, err, "should error when no ABI provided")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ABI is required")
}

func TestExtractConstructorArgs_InvalidABI(t *testing.T) {
	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, "not valid json")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid ABI JSON")
}

func TestExtractConstructorArgs_NoConstructorInputs(t *testing.T) {
	// ABI with no constructor or constructor with no inputs
	abiJSON := `[{"type":"function","name":"foo","inputs":[]}]`
	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	require.NoError(t, err)

	assert.False(t, result.HasArgs, "should report no args when ABI has no constructor inputs")
	assert.Empty(t, result.Addresses)
	assert.Equal(t, len(initCode), result.ArgsOffset)
}

func TestExtractConstructorArgs_EmptyConstructorInputs(t *testing.T) {
	// ABI with constructor but no inputs
	abiJSON := `[{"type":"constructor","inputs":[]}]`
	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	require.NoError(t, err)

	assert.False(t, result.HasArgs)
	assert.Empty(t, result.Addresses)
}

func TestExtractConstructorArgs_SingleAddress(t *testing.T) {
	// ABI with single address parameter
	abiJSON := `[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]`

	// Encode the constructor argument
	oracleAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	args := encodeConstructorArgs(t, abiJSON, oracleAddr)

	// Init code + encoded args
	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.True(t, result.HasArgs)
	assert.Len(t, result.Addresses, 1)
	assert.Equal(t, strings.ToLower(oracleAddr.Hex()), result.Addresses[0])
	assert.Len(t, result.DecodedArgs, 1)
	assert.Equal(t, "oracle", result.DecodedArgs[0].Name)
	assert.Equal(t, "address", result.DecodedArgs[0].Type)
	assert.True(t, result.DecodedArgs[0].IsAddress)
	assert.Equal(t, len(initCode), result.ArgsOffset)
}

func TestExtractConstructorArgs_MixedTypes(t *testing.T) {
	// ABI with address and uint256 (both fixed-size)
	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"owner","type":"address"},
		{"name":"value","type":"uint256"}
	]}]`

	ownerAddr := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	value := big.NewInt(12345)

	args := encodeConstructorArgs(t, abiJSON, ownerAddr, value)

	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.True(t, result.HasArgs)
	assert.Len(t, result.Addresses, 1, "should extract only the address")
	assert.Equal(t, strings.ToLower(ownerAddr.Hex()), result.Addresses[0])
	assert.Len(t, result.DecodedArgs, 2)

	// Check address arg
	assert.Equal(t, "owner", result.DecodedArgs[0].Name)
	assert.True(t, result.DecodedArgs[0].IsAddress)

	// Check uint256 arg
	assert.Equal(t, "value", result.DecodedArgs[1].Name)
	assert.False(t, result.DecodedArgs[1].IsAddress)
}

func TestExtractConstructorArgs_MultipleAddresses(t *testing.T) {
	// ABI with multiple address parameters
	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"token","type":"address"},
		{"name":"oracle","type":"address"},
		{"name":"admin","type":"address"}
	]}]`

	token := common.HexToAddress("0x1111111111111111111111111111111111111111")
	oracle := common.HexToAddress("0x2222222222222222222222222222222222222222")
	admin := common.HexToAddress("0x3333333333333333333333333333333333333333")

	args := encodeConstructorArgs(t, abiJSON, token, oracle, admin)

	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.True(t, result.HasArgs)
	assert.Len(t, result.Addresses, 3)
	assert.Contains(t, result.Addresses, strings.ToLower(token.Hex()))
	assert.Contains(t, result.Addresses, strings.ToLower(oracle.Hex()))
	assert.Contains(t, result.Addresses, strings.ToLower(admin.Hex()))
}

func TestExtractConstructorArgs_FixedAddressArray(t *testing.T) {
	// ABI with fixed-size address array
	abiJSON := `[{"type":"constructor","inputs":[{"name":"signers","type":"address[3]"}]}]`

	signers := [3]common.Address{
		common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc"),
	}

	args := encodeConstructorArgs(t, abiJSON, signers)

	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.True(t, result.HasArgs)
	assert.Len(t, result.Addresses, 3)
	for _, signer := range signers {
		assert.Contains(t, result.Addresses, strings.ToLower(signer.Hex()))
	}
}

func TestExtractConstructorArgs_DynamicArrayRejected(t *testing.T) {
	// ABI with dynamic address array - should be rejected
	abiJSON := `[{"type":"constructor","inputs":[{"name":"signers","type":"address[]"}]}]`

	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	assert.Error(t, err, "dynamic types should be rejected")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "dynamic type")
}

func TestExtractConstructorArgs_StringRejected(t *testing.T) {
	// ABI with string type - should be rejected
	abiJSON := `[{"type":"constructor","inputs":[{"name":"name","type":"string"}]}]`

	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	assert.Error(t, err, "dynamic types should be rejected")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "dynamic type")
}

func TestExtractConstructorArgs_BytesRejected(t *testing.T) {
	// ABI with bytes type - should be rejected
	abiJSON := `[{"type":"constructor","inputs":[{"name":"data","type":"bytes"}]}]`

	initCode := []byte{PUSH1, 0x00, STOP}

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	assert.Error(t, err, "dynamic types should be rejected")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "dynamic type")
}

func TestExtractConstructorArgs_Bytes32Allowed(t *testing.T) {
	// ABI with bytes32 type - should be allowed (fixed size)
	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"hash","type":"bytes32"},
		{"name":"owner","type":"address"}
	]}]`

	hash := [32]byte{0x01, 0x02, 0x03}
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	args := encodeConstructorArgs(t, abiJSON, hash, owner)

	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.True(t, result.HasArgs)
	assert.Len(t, result.Addresses, 1)
	assert.Equal(t, strings.ToLower(owner.Hex()), result.Addresses[0])
}

func TestExtractConstructorArgs_BoolAndUint(t *testing.T) {
	// ABI with bool and various uint types
	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"enabled","type":"bool"},
		{"name":"count","type":"uint8"},
		{"name":"amount","type":"uint256"},
		{"name":"admin","type":"address"}
	]}]`

	enabled := true
	count := uint8(42)
	amount := big.NewInt(1000000)
	admin := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	args := encodeConstructorArgs(t, abiJSON, enabled, count, amount, admin)

	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.True(t, result.HasArgs)
	assert.Len(t, result.Addresses, 1)
	assert.Equal(t, strings.ToLower(admin.Hex()), result.Addresses[0])
}

func TestExtractConstructorArgs_ZeroAddress(t *testing.T) {
	// Constructor with zero address should still be extracted
	abiJSON := `[{"type":"constructor","inputs":[{"name":"addr","type":"address"}]}]`

	zeroAddr := common.Address{}
	args := encodeConstructorArgs(t, abiJSON, zeroAddr)

	initCode := []byte{PUSH1, 0x00, STOP}
	bytecode := append(initCode, args...)

	result, err := ExtractConstructorArgs(bytecode, abiJSON)
	require.NoError(t, err)

	assert.Len(t, result.Addresses, 1)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", result.Addresses[0])
}

func TestExtractConstructorArgs_BytecodeTooShort(t *testing.T) {
	// ABI expects 32 bytes but bytecode is shorter
	abiJSON := `[{"type":"constructor","inputs":[{"name":"addr","type":"address"}]}]`

	// Only 10 bytes - too short for address (32 bytes)
	initCode := []byte{PUSH1, 0x00, STOP, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "exceeds bytecode length")
}

func TestExtractConstructorArgs_DecodeMismatch(t *testing.T) {
	// ABI expects address but provide malformed data
	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"addr1","type":"address"},
		{"name":"addr2","type":"address"}
	]}]`

	// Only provide 32 bytes but ABI expects 64
	initCode := make([]byte, 35) // 3 bytes init + 32 bytes (one address, but ABI expects two)
	initCode[0] = PUSH1
	initCode[1] = 0x00
	initCode[2] = STOP

	result, err := ExtractConstructorArgs(initCode, abiJSON)
	assert.Error(t, err)
	assert.Nil(t, result)
	// Either "exceeds bytecode length" or "failed to decode"
}

func TestCalculateABIEncodedSize(t *testing.T) {
	tests := []struct {
		name        string
		abiJSON     string
		expectedSize int
		expectError bool
	}{
		{
			name:        "single address",
			abiJSON:     `[{"type":"constructor","inputs":[{"name":"a","type":"address"}]}]`,
			expectedSize: 32,
		},
		{
			name:        "two addresses",
			abiJSON:     `[{"type":"constructor","inputs":[{"name":"a","type":"address"},{"name":"b","type":"address"}]}]`,
			expectedSize: 64,
		},
		{
			name:        "address and uint256",
			abiJSON:     `[{"type":"constructor","inputs":[{"name":"a","type":"address"},{"name":"b","type":"uint256"}]}]`,
			expectedSize: 64,
		},
		{
			name:        "fixed array of 3 addresses",
			abiJSON:     `[{"type":"constructor","inputs":[{"name":"a","type":"address[3]"}]}]`,
			expectedSize: 96,
		},
		{
			name:        "dynamic array",
			abiJSON:     `[{"type":"constructor","inputs":[{"name":"a","type":"address[]"}]}]`,
			expectError: true,
		},
		{
			name:        "string type",
			abiJSON:     `[{"type":"constructor","inputs":[{"name":"a","type":"string"}]}]`,
			expectError: true,
		},
		{
			name:        "no inputs",
			abiJSON:     `[{"type":"constructor","inputs":[]}]`,
			expectedSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedABI, err := abi.JSON(strings.NewReader(tt.abiJSON))
			require.NoError(t, err)

			size, err := calculateABIEncodedSize(parsedABI.Constructor.Inputs)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSize, size)
			}
		})
	}
}

// Helper function to encode constructor arguments using ABI
func encodeConstructorArgs(t *testing.T, abiJSON string, args ...any) []byte {
	t.Helper()

	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err, "failed to parse ABI")

	encoded, err := parsedABI.Constructor.Inputs.Pack(args...)
	require.NoError(t, err, "failed to encode constructor args")

	return encoded
}
