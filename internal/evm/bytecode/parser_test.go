package bytecode

import (
	"testing"
)

func TestParse_EmptyBytecode(t *testing.T) {
	bc, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bc == nil {
		t.Fatal("expected non-nil Bytecode")
	}
	if len(bc.Opcodes) != 0 {
		t.Errorf("expected 0 opcodes, got %d", len(bc.Opcodes))
	}

	bc, err = Parse([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bc.Opcodes) != 0 {
		t.Errorf("expected 0 opcodes, got %d", len(bc.Opcodes))
	}
}

func TestParse_SimpleOpcodes(t *testing.T) {
	// STOP, ADD, JUMPDEST
	bytecode := []byte{STOP, ADD, JUMPDEST}

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bc.Opcodes) != 3 {
		t.Fatalf("expected 3 opcodes, got %d", len(bc.Opcodes))
	}

	tests := []struct {
		idx    int
		code   byte
		name   string
		offset uint64
	}{
		{0, STOP, "STOP", 0},
		{1, ADD, "ADD", 1},
		{2, JUMPDEST, "JUMPDEST", 2},
	}

	for _, tt := range tests {
		op := bc.Opcodes[tt.idx]
		if op.Code != tt.code {
			t.Errorf("opcode[%d]: expected code %#x, got %#x", tt.idx, tt.code, op.Code)
		}
		if op.Name != tt.name {
			t.Errorf("opcode[%d]: expected name %q, got %q", tt.idx, tt.name, op.Name)
		}
		if op.Offset != tt.offset {
			t.Errorf("opcode[%d]: expected offset %d, got %d", tt.idx, tt.offset, op.Offset)
		}
		if len(op.Args) != 0 {
			t.Errorf("opcode[%d]: expected no args, got %d", tt.idx, len(op.Args))
		}
	}
}

func TestParse_Push1(t *testing.T) {
	// PUSH1 0x42
	bytecode := []byte{PUSH1, 0x42}

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bc.Opcodes) != 1 {
		t.Fatalf("expected 1 opcode, got %d", len(bc.Opcodes))
	}

	op := bc.Opcodes[0]
	if op.Code != PUSH1 {
		t.Errorf("expected PUSH1, got %#x", op.Code)
	}
	if op.Name != "PUSH1" {
		t.Errorf("expected name PUSH1, got %q", op.Name)
	}
	if len(op.Args) != 1 {
		t.Fatalf("expected 1 arg byte, got %d", len(op.Args))
	}
	if op.Args[0] != 0x42 {
		t.Errorf("expected arg 0x42, got %#x", op.Args[0])
	}
}

func TestParse_AllPushSizes(t *testing.T) {
	// Test PUSH1 through PUSH32
	for pushOp := PUSH1; pushOp <= PUSH32; pushOp++ {
		pushSize := int(pushOp - PUSH1 + 1)

		// Build bytecode: PUSH<N> followed by N bytes
		bytecode := make([]byte, 1+pushSize)
		bytecode[0] = pushOp
		for i := 0; i < pushSize; i++ {
			bytecode[1+i] = byte(i + 1)
		}

		bc, err := Parse(bytecode)
		if err != nil {
			t.Fatalf("PUSH%d: unexpected error: %v", pushSize, err)
		}

		if len(bc.Opcodes) != 1 {
			t.Fatalf("PUSH%d: expected 1 opcode, got %d", pushSize, len(bc.Opcodes))
		}

		op := bc.Opcodes[0]
		if op.Code != pushOp {
			t.Errorf("PUSH%d: expected opcode %#x, got %#x", pushSize, pushOp, op.Code)
		}
		if len(op.Args) != pushSize {
			t.Errorf("PUSH%d: expected %d arg bytes, got %d", pushSize, pushSize, len(op.Args))
		}

		// Verify arg content
		for i := 0; i < pushSize; i++ {
			if op.Args[i] != byte(i+1) {
				t.Errorf("PUSH%d: arg[%d] expected %d, got %d", pushSize, i, i+1, op.Args[i])
			}
		}
	}
}

func TestParse_TruncatedPush(t *testing.T) {
	// PUSH4 with only 2 bytes of data (truncated)
	bytecode := []byte{PUSH4, 0x01, 0x02}

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bc.Opcodes) != 1 {
		t.Fatalf("expected 1 opcode, got %d", len(bc.Opcodes))
	}

	op := bc.Opcodes[0]
	if op.Code != PUSH4 {
		t.Errorf("expected PUSH4, got %#x", op.Code)
	}
	// Should have only the available 2 bytes
	if len(op.Args) != 2 {
		t.Errorf("expected 2 arg bytes (truncated), got %d", len(op.Args))
	}
}

func TestParse_MixedOpcodes(t *testing.T) {
	// PUSH1 0x80 PUSH2 0x01 0x02 DUP1 CALL
	bytecode := []byte{
		PUSH1, 0x80,
		PUSH2, 0x01, 0x02,
		DUP1,
		CALL,
	}

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bc.Opcodes) != 4 {
		t.Fatalf("expected 4 opcodes, got %d", len(bc.Opcodes))
	}

	// Verify offsets
	expectedOffsets := []uint64{0, 2, 5, 6}
	for i, expected := range expectedOffsets {
		if bc.Opcodes[i].Offset != expected {
			t.Errorf("opcode[%d]: expected offset %d, got %d", i, expected, bc.Opcodes[i].Offset)
		}
	}
}

func TestParseHex(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "empty string",
			input:     "",
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "0x prefix",
			input:     "0x6080",
			wantCount: 1, // PUSH1 0x80
			wantErr:   false,
		},
		{
			name:      "no prefix",
			input:     "6080",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "uppercase hex",
			input:     "0x6080DEADBEEF",
			wantCount: 5, // PUSH1 0x80, 0xDE, 0xAD, 0xBE, 0xEF (unknown opcodes)
			wantErr:   false,
		},
		{
			name:      "invalid hex",
			input:     "0xGGGG",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "odd length hex",
			input:     "0x608",
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc, err := ParseHex(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(bc.Opcodes) != tt.wantCount {
				t.Errorf("expected %d opcodes, got %d", tt.wantCount, len(bc.Opcodes))
			}
		})
	}
}

func TestBytecode_HasOpcode(t *testing.T) {
	bytecode := []byte{PUSH1, 0x80, CALL, STOP}
	bc, _ := Parse(bytecode)

	tests := []struct {
		op   byte
		want bool
	}{
		{PUSH1, true},
		{CALL, true},
		{STOP, true},
		{DELEGATECALL, false},
		{CREATE, false},
	}

	for _, tt := range tests {
		got := bc.HasOpcode(tt.op)
		if got != tt.want {
			t.Errorf("HasOpcode(%#x): expected %v, got %v", tt.op, tt.want, got)
		}
	}
}

func TestBytecode_FindOpcodes(t *testing.T) {
	// Multiple PUSH1 instructions
	bytecode := []byte{PUSH1, 0x01, PUSH1, 0x02, PUSH2, 0x03, 0x04, PUSH1, 0x05}
	bc, _ := Parse(bytecode)

	push1s := bc.FindOpcodes(PUSH1)
	if len(push1s) != 3 {
		t.Fatalf("expected 3 PUSH1 opcodes, got %d", len(push1s))
	}

	// Verify the args are correct
	expectedArgs := []byte{0x01, 0x02, 0x05}
	for i, op := range push1s {
		if len(op.Args) != 1 || op.Args[0] != expectedArgs[i] {
			t.Errorf("PUSH1[%d]: expected arg %#x, got %v", i, expectedArgs[i], op.Args)
		}
	}

	// Non-existent opcode
	nops := bc.FindOpcodes(CALL)
	if len(nops) != 0 {
		t.Errorf("expected 0 CALL opcodes, got %d", len(nops))
	}
}

func TestBytecode_FindCallOpcodes(t *testing.T) {
	bytecode := []byte{
		PUSH1, 0x00, // gas
		PUSH20, // address (20 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14,
		CALL,
		STATICCALL,
		DELEGATECALL,
		STOP,
	}

	bc, _ := Parse(bytecode)
	calls := bc.FindCallOpcodes()

	if len(calls) != 3 {
		t.Fatalf("expected 3 call opcodes, got %d", len(calls))
	}

	expectedCalls := []byte{CALL, STATICCALL, DELEGATECALL}
	for i, c := range calls {
		if c.Code != expectedCalls[i] {
			t.Errorf("call[%d]: expected %#x, got %#x", i, expectedCalls[i], c.Code)
		}
	}
}

func TestBytecode_FindCreateOpcodes(t *testing.T) {
	bytecode := []byte{CREATE, PUSH1, 0x00, CREATE2, STOP}
	bc, _ := Parse(bytecode)

	creates := bc.FindCreateOpcodes()
	if len(creates) != 2 {
		t.Fatalf("expected 2 create opcodes, got %d", len(creates))
	}

	if creates[0].Code != CREATE || creates[1].Code != CREATE2 {
		t.Error("unexpected create opcodes")
	}
}

func TestBytecode_FindPushOpcodes(t *testing.T) {
	bytecode := []byte{PUSH1, 0x01, PUSH32}
	// Add 32 bytes for PUSH32
	for i := 0; i < 32; i++ {
		bytecode = append(bytecode, byte(i))
	}
	bytecode = append(bytecode, STOP)

	bc, _ := Parse(bytecode)
	pushes := bc.FindPushOpcodes()

	if len(pushes) != 2 {
		t.Fatalf("expected 2 push opcodes, got %d", len(pushes))
	}
}

func TestBytecode_OpcodeCount(t *testing.T) {
	bytecode := []byte{PUSH1, 0x80, PUSH1, 0x40, ADD, STOP}
	bc, _ := Parse(bytecode)

	if bc.OpcodeCount() != 4 {
		t.Errorf("expected 4 opcodes, got %d", bc.OpcodeCount())
	}
}

func TestBytecode_IsEmpty(t *testing.T) {
	bc1, _ := Parse(nil)
	if !bc1.IsEmpty() {
		t.Error("expected empty bytecode")
	}

	bc2, _ := Parse([]byte{STOP})
	if bc2.IsEmpty() {
		t.Error("expected non-empty bytecode")
	}
}

func TestBytecode_GetOpcodeAt(t *testing.T) {
	bytecode := []byte{PUSH2, 0x01, 0x02, STOP}
	bc, _ := Parse(bytecode)

	op := bc.GetOpcodeAt(0)
	if op == nil || op.Code != PUSH2 {
		t.Error("expected PUSH2 at offset 0")
	}

	op = bc.GetOpcodeAt(3)
	if op == nil || op.Code != STOP {
		t.Error("expected STOP at offset 3")
	}

	op = bc.GetOpcodeAt(1)
	if op != nil {
		t.Error("expected nil for offset within PUSH arguments")
	}

	op = bc.GetOpcodeAt(100)
	if op != nil {
		t.Error("expected nil for invalid offset")
	}
}

func TestParse_UnknownOpcodes(t *testing.T) {
	// 0x0C is currently undefined
	bytecode := []byte{0x0C, STOP}
	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bc.Opcodes) != 2 {
		t.Fatalf("expected 2 opcodes, got %d", len(bc.Opcodes))
	}

	if bc.Opcodes[0].Name != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %q", bc.Opcodes[0].Name)
	}
}
