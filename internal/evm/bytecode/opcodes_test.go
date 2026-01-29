package bytecode

import (
	"testing"
)

func TestIsPushOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{PUSH1, true},
		{PUSH2, true},
		{PUSH16, true},
		{PUSH20, true},
		{PUSH32, true},
		{STOP, false},
		{CALL, false},
		{DUP1, false},
		{0x5F, false}, // before PUSH1
		{0x80, false}, // after PUSH32 (DUP1)
	}

	for _, tt := range tests {
		got := IsPushOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsPushOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestPushSize(t *testing.T) {
	tests := []struct {
		op   byte
		want int
	}{
		{PUSH1, 1},
		{PUSH2, 2},
		{PUSH4, 4},
		{PUSH8, 8},
		{PUSH16, 16},
		{PUSH20, 20},
		{PUSH32, 32},
		{STOP, 0},
		{CALL, 0},
		{DUP1, 0},
	}

	for _, tt := range tests {
		got := PushSize(tt.op)
		if got != tt.want {
			t.Errorf("PushSize(%#x) = %d, want %d", tt.op, got, tt.want)
		}
	}
}

func TestIsDupOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{DUP1, true},
		{DUP2, true},
		{DUP16, true},
		{SWAP1, false},
		{PUSH1, false},
		{CALL, false},
	}

	for _, tt := range tests {
		got := IsDupOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsDupOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestIsSwapOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{SWAP1, true},
		{SWAP2, true},
		{SWAP16, true},
		{DUP1, false},
		{PUSH1, false},
		{CALL, false},
	}

	for _, tt := range tests {
		got := IsSwapOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsSwapOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestIsLogOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{LOG0, true},
		{LOG1, true},
		{LOG2, true},
		{LOG3, true},
		{LOG4, true},
		{CALL, false},
		{PUSH1, false},
	}

	for _, tt := range tests {
		got := IsLogOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsLogOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestIsCallOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{CALL, true},
		{CALLCODE, true},
		{DELEGATECALL, true},
		{STATICCALL, true},
		{CREATE, false},
		{CREATE2, false},
		{PUSH1, false},
		{STOP, false},
	}

	for _, tt := range tests {
		got := IsCallOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsCallOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestIsCreateOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{CREATE, true},
		{CREATE2, true},
		{CALL, false},
		{DELEGATECALL, false},
		{PUSH1, false},
	}

	for _, tt := range tests {
		got := IsCreateOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsCreateOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestIsTerminalOpcode(t *testing.T) {
	tests := []struct {
		op   byte
		want bool
	}{
		{STOP, true},
		{RETURN, true},
		{REVERT, true},
		{INVALID, true},
		{SELFDESTRUCT, true},
		{CALL, false},
		{JUMP, false},
		{JUMPI, false},
	}

	for _, tt := range tests {
		got := IsTerminalOpcode(tt.op)
		if got != tt.want {
			t.Errorf("IsTerminalOpcode(%#x) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestGetOpcodeName(t *testing.T) {
	tests := []struct {
		op   byte
		want string
	}{
		{STOP, "STOP"},
		{ADD, "ADD"},
		{PUSH1, "PUSH1"},
		{PUSH20, "PUSH20"},
		{PUSH32, "PUSH32"},
		{CALL, "CALL"},
		{DELEGATECALL, "DELEGATECALL"},
		{STATICCALL, "STATICCALL"},
		{CREATE, "CREATE"},
		{CREATE2, "CREATE2"},
		{SELFDESTRUCT, "SELFDESTRUCT"},
		{0x0C, "UNKNOWN"}, // undefined opcode
		{0xB0, "UNKNOWN"}, // undefined opcode
	}

	for _, tt := range tests {
		got := GetOpcodeName(tt.op)
		if got != tt.want {
			t.Errorf("GetOpcodeName(%#x) = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestOpcodeConstants(t *testing.T) {
	// Verify some key opcode values match the EVM specification
	tests := []struct {
		name  string
		op    byte
		value byte
	}{
		{"STOP", STOP, 0x00},
		{"ADD", ADD, 0x01},
		{"SHA3", SHA3, 0x20},
		{"ADDRESS", ADDRESS, 0x30},
		{"CALLDATALOAD", CALLDATALOAD, 0x35},
		{"SLOAD", SLOAD, 0x54},
		{"JUMPDEST", JUMPDEST, 0x5B},
		{"PUSH1", PUSH1, 0x60},
		{"PUSH20", PUSH20, 0x73},
		{"PUSH32", PUSH32, 0x7F},
		{"DUP1", DUP1, 0x80},
		{"SWAP1", SWAP1, 0x90},
		{"LOG0", LOG0, 0xA0},
		{"CREATE", CREATE, 0xF0},
		{"CALL", CALL, 0xF1},
		{"CALLCODE", CALLCODE, 0xF2},
		{"RETURN", RETURN, 0xF3},
		{"DELEGATECALL", DELEGATECALL, 0xF4},
		{"CREATE2", CREATE2, 0xF5},
		{"STATICCALL", STATICCALL, 0xFA},
		{"REVERT", REVERT, 0xFD},
		{"INVALID", INVALID, 0xFE},
		{"SELFDESTRUCT", SELFDESTRUCT, 0xFF},
	}

	for _, tt := range tests {
		if tt.op != tt.value {
			t.Errorf("%s: expected %#x, got %#x", tt.name, tt.value, tt.op)
		}
	}
}

func TestOpcodeNamesComplete(t *testing.T) {
	// Verify all defined constants have names
	constants := []byte{
		STOP, ADD, MUL, SUB, DIV, MOD,
		LT, GT, EQ, ISZERO, AND, OR, XOR, NOT,
		SHA3,
		ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD,
		CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE,
		EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY, EXTCODEHASH,
		BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT,
		CHAINID, SELFBALANCE, BASEFEE,
		POP, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, JUMP, JUMPI,
		PC, MSIZE, GAS, JUMPDEST,
		PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8,
		PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16,
		PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24,
		PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32,
		DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8,
		DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16,
		SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8,
		SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16,
		LOG0, LOG1, LOG2, LOG3, LOG4,
		CREATE, CALL, CALLCODE, RETURN, DELEGATECALL, CREATE2,
		STATICCALL, REVERT, INVALID, SELFDESTRUCT,
	}

	for _, op := range constants {
		name := OpcodeNames[op]
		if name == "" {
			t.Errorf("opcode %#x has no name in OpcodeNames map", op)
		}
	}
}
