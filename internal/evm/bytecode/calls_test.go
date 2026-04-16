package bytecode

import (
	"testing"
)

func TestExtractCallTargets_NilBytecode(t *testing.T) {
	result := ExtractCallTargets(nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.CallTargets) != 0 {
		t.Errorf("expected 0 call targets, got %d", len(result.CallTargets))
	}
}

func TestExtractCallTargets_EmptyBytecode(t *testing.T) {
	bc, _ := Parse([]byte{})
	result := ExtractCallTargets(bc)
	if len(result.CallTargets) != 0 {
		t.Errorf("expected 0 call targets, got %d", len(result.CallTargets))
	}
}

func TestExtractCallTargets_NoCallOpcodes(t *testing.T) {
	bc, _ := Parse([]byte{PUSH1, 0x80, STOP})
	result := ExtractCallTargets(bc)
	if len(result.CallTargets) != 0 {
		t.Errorf("expected 0 call targets, got %d", len(result.CallTargets))
	}
	if result.HasDynamicCall {
		t.Error("expected HasDynamicCall to be false")
	}
}

func TestExtractCallTargets_ConstantAddress(t *testing.T) {
	// PUSH1 gas, PUSH20 address, CALL
	address := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	bytecode := []byte{PUSH1, 0x00} // gas
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, address...)
	bytecode = append(bytecode, CALL)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.OpcodeName != "CALL" {
		t.Errorf("expected CALL, got %s", target.OpcodeName)
	}
	if target.TargetType != CallTargetConstant {
		t.Errorf("expected constant target, got %s", target.TargetType)
	}
	if target.Address != "0xdeadbeef00112233445566778899aabbccddeeff" {
		t.Errorf("unexpected address: %s", target.Address)
	}
	if target.SourceOp != "PUSH20" {
		t.Errorf("expected source PUSH20, got %s", target.SourceOp)
	}

	// Check unique addresses
	if len(result.ConstantAddrs) != 1 {
		t.Errorf("expected 1 constant address, got %d", len(result.ConstantAddrs))
	}
}

func TestExtractCallTargets_DynamicFromSLOAD(t *testing.T) {
	// PUSH1 slot, SLOAD, CALL
	bytecode := []byte{
		PUSH1, 0x00, // slot
		SLOAD,      // load address from storage
		PUSH1, 0x00, // gas
		CALL,
	}

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.TargetType != CallTargetDynamic {
		t.Errorf("expected dynamic target, got %s", target.TargetType)
	}
	if target.SourceOp != "SLOAD" {
		t.Errorf("expected source SLOAD, got %s", target.SourceOp)
	}
	if target.Address != "" {
		t.Errorf("expected empty address for dynamic call, got %s", target.Address)
	}
	if !result.HasDynamicCall {
		t.Error("expected HasDynamicCall to be true")
	}
}

func TestExtractCallTargets_DynamicFromCALLDATALOAD(t *testing.T) {
	// CALLDATALOAD followed by CALL
	bytecode := []byte{
		PUSH1, 0x04, // offset
		CALLDATALOAD, // load address from calldata
		PUSH1, 0x00, // gas
		STATICCALL,
	}

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.TargetType != CallTargetDynamic {
		t.Errorf("expected dynamic target, got %s", target.TargetType)
	}
	if target.SourceOp != "CALLDATALOAD" {
		t.Errorf("expected source CALLDATALOAD, got %s", target.SourceOp)
	}
	if target.OpcodeName != "STATICCALL" {
		t.Errorf("expected STATICCALL, got %s", target.OpcodeName)
	}
}

func TestExtractCallTargets_DynamicFromMLOAD(t *testing.T) {
	bytecode := []byte{
		PUSH1, 0x20, // offset
		MLOAD,       // load address from memory
		PUSH1, 0x00, // gas
		DELEGATECALL,
	}

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.TargetType != CallTargetDynamic {
		t.Errorf("expected dynamic target, got %s", target.TargetType)
	}
	if target.SourceOp != "MLOAD" {
		t.Errorf("expected source MLOAD, got %s", target.SourceOp)
	}
	if !result.HasDelegateCall {
		t.Error("expected HasDelegateCall to be true")
	}
}

func TestExtractCallTargets_CREATE(t *testing.T) {
	bytecode := []byte{CREATE, STOP}
	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}
	if result.HasCreate2 {
		t.Error("expected HasCreate2 to be false")
	}
}

func TestExtractCallTargets_CREATE2(t *testing.T) {
	bytecode := []byte{CREATE2, STOP}
	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if result.HasCreate {
		t.Error("expected HasCreate to be false")
	}
	if !result.HasCreate2 {
		t.Error("expected HasCreate2 to be true")
	}
}

func TestExtractCallTargets_SELFDESTRUCT(t *testing.T) {
	bytecode := []byte{PUSH20}
	// Add 20-byte address
	for i := 0; i < 20; i++ {
		bytecode = append(bytecode, byte(i))
	}
	bytecode = append(bytecode, SELFDESTRUCT)

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if !result.HasSelfDestruct {
		t.Error("expected HasSelfDestruct to be true")
	}
}

func TestExtractCallTargets_MultipleCallsWithDifferentTargets(t *testing.T) {
	// First call: constant address
	addr1 := make([]byte, 20)
	for i := range addr1 {
		addr1[i] = byte(i + 1)
	}

	// Second call: same constant address (should dedupe)
	// Third call: dynamic from SLOAD

	bytecode := []byte{PUSH1, 0x00}
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, addr1...)
	bytecode = append(bytecode, CALL)

	bytecode = append(bytecode, PUSH1, 0x00)
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, addr1...) // same address
	bytecode = append(bytecode, STATICCALL)

	bytecode = append(bytecode, PUSH1, 0x00, SLOAD, PUSH1, 0x00, CALL)

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if len(result.CallTargets) != 3 {
		t.Fatalf("expected 3 call targets, got %d", len(result.CallTargets))
	}

	// Should have only 1 unique constant address (deduped)
	if len(result.ConstantAddrs) != 1 {
		t.Errorf("expected 1 unique constant address, got %d", len(result.ConstantAddrs))
	}

	// Should have dynamic call
	if !result.HasDynamicCall {
		t.Error("expected HasDynamicCall to be true")
	}

	// Verify call types
	if result.CallTargets[0].OpcodeName != "CALL" {
		t.Errorf("first call: expected CALL, got %s", result.CallTargets[0].OpcodeName)
	}
	if result.CallTargets[1].OpcodeName != "STATICCALL" {
		t.Errorf("second call: expected STATICCALL, got %s", result.CallTargets[1].OpcodeName)
	}
}

func TestExtractCallTargets_PUSH32WithPaddedAddress(t *testing.T) {
	// PUSH32 with 12 zero bytes followed by 20-byte address
	bytecode := []byte{PUSH1, 0x00}
	bytecode = append(bytecode, PUSH32)
	// 12 zero bytes
	for i := 0; i < 12; i++ {
		bytecode = append(bytecode, 0x00)
	}
	// 20-byte address
	addr := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	bytecode = append(bytecode, addr...)
	bytecode = append(bytecode, CALL)

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.TargetType != CallTargetConstant {
		t.Errorf("expected constant target, got %s", target.TargetType)
	}
	if target.SourceOp != "PUSH32" {
		t.Errorf("expected source PUSH32, got %s", target.SourceOp)
	}
	if target.Address != "0xdeadbeef00112233445566778899aabbccddeeff" {
		t.Errorf("unexpected address: %s", target.Address)
	}
}

func TestExtractCallTargets_UnknownSource(t *testing.T) {
	// CALL with no identifiable address source
	bytecode := []byte{CALL}

	bc, _ := Parse(bytecode)
	result := ExtractCallTargets(bc)

	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.TargetType != CallTargetUnknown {
		t.Errorf("expected unknown target, got %s", target.TargetType)
	}
	// Unknown is treated as dynamic for safety
	if !result.HasDynamicCall {
		t.Error("expected HasDynamicCall to be true for unknown source")
	}
}

func TestExtractCallTargets_AllCallVariants(t *testing.T) {
	// Test all four call variants
	address := make([]byte, 20)
	for i := range address {
		address[i] = 0xAB
	}

	tests := []struct {
		name   string
		opcode byte
	}{
		{"CALL", CALL},
		{"CALLCODE", CALLCODE},
		{"DELEGATECALL", DELEGATECALL},
		{"STATICCALL", STATICCALL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytecode := []byte{PUSH1, 0x00}
			bytecode = append(bytecode, PUSH20)
			bytecode = append(bytecode, address...)
			bytecode = append(bytecode, tt.opcode)

			bc, _ := Parse(bytecode)
			result := ExtractCallTargets(bc)

			if len(result.CallTargets) != 1 {
				t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
			}

			if result.CallTargets[0].OpcodeName != tt.name {
				t.Errorf("expected %s, got %s", tt.name, result.CallTargets[0].OpcodeName)
			}
		})
	}
}

func TestExtractPush20Addresses(t *testing.T) {
	addr1 := make([]byte, 20)
	addr2 := make([]byte, 20)
	for i := range addr1 {
		addr1[i] = byte(i + 1)
		addr2[i] = byte(i + 0x10)
	}

	bytecode := []byte{}
	// First address
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, addr1...)
	// Second address
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, addr2...)
	// Duplicate of first address (should be deduped)
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, addr1...)
	bytecode = append(bytecode, STOP)

	bc, _ := Parse(bytecode)
	addresses := ExtractPush20Addresses(bc)

	if len(addresses) != 2 {
		t.Fatalf("expected 2 unique addresses, got %d", len(addresses))
	}
}

func TestAnalysisResult_SummarizeAnalysis(t *testing.T) {
	result := &AnalysisResult{
		CallTargets:     []CallTarget{{OpcodeName: "CALL"}},
		HasDynamicCall:  true,
		ConstantAddrs:   []string{"0xabc", "0xdef"},
		HasCreate:       true,
		HasCreate2:      false,
		HasSelfDestruct: false,
		HasDelegateCall: true,
	}

	summary := result.SummarizeAnalysis()

	if summary["total_calls"].(int) != 1 {
		t.Errorf("expected total_calls=1, got %v", summary["total_calls"])
	}
	if summary["has_dynamic_calls"].(bool) != true {
		t.Error("expected has_dynamic_calls=true")
	}
	if summary["has_create"].(bool) != true {
		t.Error("expected has_create=true")
	}
	if summary["has_delegatecall"].(bool) != true {
		t.Error("expected has_delegatecall=true")
	}

	addrs := summary["constant_addresses"].([]string)
	if len(addrs) != 2 {
		t.Errorf("expected 2 constant addresses, got %d", len(addrs))
	}
}

// =============================================================================
// Security tests: PUSH argument bytes must NOT be detected as opcodes
// =============================================================================

// TestExtractCallTargets_CREATE_InPUSH32Args_NotDetected verifies that 0xf0 (CREATE)
// bytes inside PUSH32 arguments are not misdetected as CREATE opcodes.
// P0: if this fails, attackers can bypass CREATE detection by hiding it in PUSH args.
func TestExtractCallTargets_CREATE_InPUSH32Args_NotDetected(t *testing.T) {
	// PUSH32 with 32 bytes all equal to 0xf0 (CREATE opcode value), then STOP
	bc_bytes := make([]byte, 0, 34)
	bc_bytes = append(bc_bytes, PUSH32) // 0x7f
	for i := 0; i < 32; i++ {
		bc_bytes = append(bc_bytes, 0xf0) // CREATE opcode value as data
	}
	bc_bytes = append(bc_bytes, STOP)

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if result.HasCreate {
		t.Error("HasCreate should be false: 0xf0 bytes are PUSH32 arguments, not CREATE opcodes")
	}
}

// TestExtractCallTargets_CREATE2_InPUSH32Args_NotDetected verifies that 0xf5 (CREATE2)
// bytes inside PUSH32 arguments are not misdetected as CREATE2 opcodes.
func TestExtractCallTargets_CREATE2_InPUSH32Args_NotDetected(t *testing.T) {
	bc_bytes := make([]byte, 0, 34)
	bc_bytes = append(bc_bytes, PUSH32) // 0x7f
	for i := 0; i < 32; i++ {
		bc_bytes = append(bc_bytes, 0xf5) // CREATE2 opcode value as data
	}
	bc_bytes = append(bc_bytes, STOP)

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if result.HasCreate2 {
		t.Error("HasCreate2 should be false: 0xf5 bytes are PUSH32 arguments, not CREATE2 opcodes")
	}
}

// TestExtractCallTargets_DELEGATECALL_InPUSH1Arg_NotDetected verifies that 0xf4 (DELEGATECALL)
// as a PUSH1 argument is not misdetected as a DELEGATECALL opcode.
func TestExtractCallTargets_DELEGATECALL_InPUSH1Arg_NotDetected(t *testing.T) {
	// PUSH1 0xf4 (DELEGATECALL value as data), STOP
	bc_bytes := []byte{PUSH1, 0xf4, STOP}

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if result.HasDynamicCall {
		t.Error("HasDynamicCall should be false: 0xf4 is a PUSH1 argument, not a DELEGATECALL opcode")
	}
	if len(result.CallTargets) != 0 {
		t.Errorf("expected 0 call targets, got %d", len(result.CallTargets))
	}
	if result.HasDelegateCall {
		t.Error("HasDelegateCall should be false: 0xf4 is a PUSH1 argument, not a DELEGATECALL opcode")
	}
}

// TestExtractCallTargets_AllDangerousOpcodesInPUSH32_NoneDetected verifies that
// all dangerous opcode byte values (0xf0-0xf5) embedded as PUSH32 data are not
// misdetected as actual opcodes.
func TestExtractCallTargets_AllDangerousOpcodesInPUSH32_NoneDetected(t *testing.T) {
	// PUSH32 with first 6 bytes being dangerous opcode values, rest zeros, then STOP
	pushArgs := []byte{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, // CREATE, CALL, CALLCODE, RETURN, DELEGATECALL, CREATE2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	bc_bytes := make([]byte, 0, 34)
	bc_bytes = append(bc_bytes, PUSH32)
	bc_bytes = append(bc_bytes, pushArgs...)
	bc_bytes = append(bc_bytes, STOP)

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if result.HasCreate {
		t.Error("HasCreate should be false: all dangerous bytes are PUSH32 arguments")
	}
	if result.HasCreate2 {
		t.Error("HasCreate2 should be false: all dangerous bytes are PUSH32 arguments")
	}
	if result.HasDynamicCall {
		t.Error("HasDynamicCall should be false: all dangerous bytes are PUSH32 arguments")
	}
	if len(result.CallTargets) != 0 {
		t.Errorf("expected 0 call targets, got %d", len(result.CallTargets))
	}
}

// TestExtractCallTargets_ZeroAddress_RequiresOrgOwnership verifies that the zero address
// (0x0000...0000) is treated as a constant call target. The deploy validator will then
// check org ownership, blocking it if not org-owned.
func TestExtractCallTargets_ZeroAddress_RequiresOrgOwnership(t *testing.T) {
	// PUSH20 <20 zero bytes> CALL STOP
	bc_bytes := make([]byte, 0, 23)
	bc_bytes = append(bc_bytes, PUSH20)
	for i := 0; i < 20; i++ {
		bc_bytes = append(bc_bytes, 0x00)
	}
	bc_bytes = append(bc_bytes, CALL, STOP)

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	target := result.CallTargets[0]
	if target.TargetType != CallTargetConstant {
		t.Errorf("expected constant target type, got %s", target.TargetType)
	}
	if target.Address != "0x0000000000000000000000000000000000000000" {
		t.Errorf("expected zero address, got %s", target.Address)
	}
}

// TestExtractCallTargets_AllFFFF_Address_TreatedAsNotConstant verifies that
// 0xffffffffffffffffffffffffffffffffffffffff is skipped as an address mask,
// not treated as a constant call target.
func TestExtractCallTargets_AllFFFF_Address_TreatedAsNotConstant(t *testing.T) {
	// PUSH20 <20 bytes of 0xff> CALL STOP
	bc_bytes := make([]byte, 0, 23)
	bc_bytes = append(bc_bytes, PUSH20)
	for i := 0; i < 20; i++ {
		bc_bytes = append(bc_bytes, 0xff)
	}
	bc_bytes = append(bc_bytes, CALL, STOP)

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	// The all-ones address is explicitly skipped as an address mask in findAddressSource.
	// The call target should be treated as unknown (not constant), which means dynamic.
	target := result.CallTargets[0]
	if target.TargetType == CallTargetConstant && target.Address == "0xffffffffffffffffffffffffffffffffffffffff" {
		t.Error("all-0xff address mask should NOT be extracted as a constant address target")
	}
	if !result.HasDynamicCall {
		t.Error("expected HasDynamicCall to be true since the address mask is skipped")
	}
}

// TestExtractCallTargets_PUSH20BeyondWindow_TreatedAsDynamic verifies that a PUSH20
// opcode beyond the 50-opcode large window is not associated with a CALL, causing
// the call target to be treated as dynamic/unknown.
func TestExtractCallTargets_PUSH20BeyondWindow_TreatedAsDynamic(t *testing.T) {
	// Build: PUSH20 <address> then 55 JUMPDEST opcodes, then CALL
	// PUSH20 is at opcode index 0, CALL is at opcode index 56 (0 + 1 + 55)
	// The large window is 50, so PUSH20 at index 0 is out of range (callIndex - 50 = 6)
	address := make([]byte, 20)
	for i := range address {
		address[i] = byte(i + 1)
	}

	bc_bytes := make([]byte, 0, 77)
	bc_bytes = append(bc_bytes, PUSH20)
	bc_bytes = append(bc_bytes, address...)
	for i := 0; i < 55; i++ {
		bc_bytes = append(bc_bytes, JUMPDEST) // 0x5b
	}
	bc_bytes = append(bc_bytes, CALL)

	bc, err := Parse(bc_bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := ExtractCallTargets(bc)
	if len(result.CallTargets) != 1 {
		t.Fatalf("expected 1 call target, got %d", len(result.CallTargets))
	}

	// PUSH20 at index 0 is beyond the 50-opcode window from CALL at index 56
	if !result.HasDynamicCall {
		t.Error("expected HasDynamicCall to be true: PUSH20 is beyond the 50-opcode window")
	}
}
