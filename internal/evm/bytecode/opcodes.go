// Package bytecode provides EVM bytecode parsing and analysis.
package bytecode

// EVM Opcodes
const (
	// Stop and arithmetic
	STOP byte = 0x00
	ADD  byte = 0x01
	MUL  byte = 0x02
	SUB  byte = 0x03
	DIV  byte = 0x04
	MOD  byte = 0x06

	// Comparison and bitwise
	LT     byte = 0x10
	GT     byte = 0x11
	EQ     byte = 0x14
	ISZERO byte = 0x15
	AND    byte = 0x16
	OR     byte = 0x17
	XOR    byte = 0x18
	NOT    byte = 0x19

	// SHA3
	SHA3 byte = 0x20

	// Environment
	ADDRESS        byte = 0x30
	BALANCE        byte = 0x31
	ORIGIN         byte = 0x32
	CALLER         byte = 0x33
	CALLVALUE      byte = 0x34
	CALLDATALOAD   byte = 0x35
	CALLDATASIZE   byte = 0x36
	CALLDATACOPY   byte = 0x37
	CODESIZE       byte = 0x38
	CODECOPY       byte = 0x39
	GASPRICE       byte = 0x3A
	EXTCODESIZE    byte = 0x3B
	EXTCODECOPY    byte = 0x3C
	RETURNDATASIZE byte = 0x3D
	RETURNDATACOPY byte = 0x3E
	EXTCODEHASH    byte = 0x3F

	// Block information
	BLOCKHASH   byte = 0x40
	COINBASE    byte = 0x41
	TIMESTAMP   byte = 0x42
	NUMBER      byte = 0x43
	DIFFICULTY  byte = 0x44
	GASLIMIT    byte = 0x45
	CHAINID     byte = 0x46
	SELFBALANCE byte = 0x47
	BASEFEE     byte = 0x48

	// Stack, memory, storage
	POP      byte = 0x50
	MLOAD    byte = 0x51
	MSTORE   byte = 0x52
	MSTORE8  byte = 0x53
	SLOAD    byte = 0x54
	SSTORE   byte = 0x55
	JUMP     byte = 0x56
	JUMPI    byte = 0x57
	PC       byte = 0x58
	MSIZE    byte = 0x59
	GAS      byte = 0x5A
	JUMPDEST byte = 0x5B

	// Push operations (PUSH1-PUSH32)
	PUSH1  byte = 0x60
	PUSH2  byte = 0x61
	PUSH3  byte = 0x62
	PUSH4  byte = 0x63
	PUSH5  byte = 0x64
	PUSH6  byte = 0x65
	PUSH7  byte = 0x66
	PUSH8  byte = 0x67
	PUSH9  byte = 0x68
	PUSH10 byte = 0x69
	PUSH11 byte = 0x6A
	PUSH12 byte = 0x6B
	PUSH13 byte = 0x6C
	PUSH14 byte = 0x6D
	PUSH15 byte = 0x6E
	PUSH16 byte = 0x6F
	PUSH17 byte = 0x70
	PUSH18 byte = 0x71
	PUSH19 byte = 0x72
	PUSH20 byte = 0x73
	PUSH21 byte = 0x74
	PUSH22 byte = 0x75
	PUSH23 byte = 0x76
	PUSH24 byte = 0x77
	PUSH25 byte = 0x78
	PUSH26 byte = 0x79
	PUSH27 byte = 0x7A
	PUSH28 byte = 0x7B
	PUSH29 byte = 0x7C
	PUSH30 byte = 0x7D
	PUSH31 byte = 0x7E
	PUSH32 byte = 0x7F

	// Dup operations (DUP1-DUP16)
	DUP1  byte = 0x80
	DUP2  byte = 0x81
	DUP3  byte = 0x82
	DUP4  byte = 0x83
	DUP5  byte = 0x84
	DUP6  byte = 0x85
	DUP7  byte = 0x86
	DUP8  byte = 0x87
	DUP9  byte = 0x88
	DUP10 byte = 0x89
	DUP11 byte = 0x8A
	DUP12 byte = 0x8B
	DUP13 byte = 0x8C
	DUP14 byte = 0x8D
	DUP15 byte = 0x8E
	DUP16 byte = 0x8F

	// Swap operations (SWAP1-SWAP16)
	SWAP1  byte = 0x90
	SWAP2  byte = 0x91
	SWAP3  byte = 0x92
	SWAP4  byte = 0x93
	SWAP5  byte = 0x94
	SWAP6  byte = 0x95
	SWAP7  byte = 0x96
	SWAP8  byte = 0x97
	SWAP9  byte = 0x98
	SWAP10 byte = 0x99
	SWAP11 byte = 0x9A
	SWAP12 byte = 0x9B
	SWAP13 byte = 0x9C
	SWAP14 byte = 0x9D
	SWAP15 byte = 0x9E
	SWAP16 byte = 0x9F

	// Log operations
	LOG0 byte = 0xA0
	LOG1 byte = 0xA1
	LOG2 byte = 0xA2
	LOG3 byte = 0xA3
	LOG4 byte = 0xA4

	// System operations
	CREATE       byte = 0xF0
	CALL         byte = 0xF1
	CALLCODE     byte = 0xF2 // Deprecated but must detect
	RETURN       byte = 0xF3
	DELEGATECALL byte = 0xF4
	CREATE2      byte = 0xF5
	STATICCALL   byte = 0xFA
	REVERT       byte = 0xFD
	INVALID      byte = 0xFE
	SELFDESTRUCT byte = 0xFF
)

// OpcodeNames maps opcode bytes to their human-readable names.
var OpcodeNames = map[byte]string{
	// Stop and arithmetic
	STOP: "STOP",
	ADD:  "ADD",
	MUL:  "MUL",
	SUB:  "SUB",
	DIV:  "DIV",
	MOD:  "MOD",

	// Comparison and bitwise
	LT:     "LT",
	GT:     "GT",
	EQ:     "EQ",
	ISZERO: "ISZERO",
	AND:    "AND",
	OR:     "OR",
	XOR:    "XOR",
	NOT:    "NOT",

	// SHA3
	SHA3: "SHA3",

	// Environment
	ADDRESS:        "ADDRESS",
	BALANCE:        "BALANCE",
	ORIGIN:         "ORIGIN",
	CALLER:         "CALLER",
	CALLVALUE:      "CALLVALUE",
	CALLDATALOAD:   "CALLDATALOAD",
	CALLDATASIZE:   "CALLDATASIZE",
	CALLDATACOPY:   "CALLDATACOPY",
	CODESIZE:       "CODESIZE",
	CODECOPY:       "CODECOPY",
	GASPRICE:       "GASPRICE",
	EXTCODESIZE:    "EXTCODESIZE",
	EXTCODECOPY:    "EXTCODECOPY",
	RETURNDATASIZE: "RETURNDATASIZE",
	RETURNDATACOPY: "RETURNDATACOPY",
	EXTCODEHASH:    "EXTCODEHASH",

	// Block information
	BLOCKHASH:   "BLOCKHASH",
	COINBASE:    "COINBASE",
	TIMESTAMP:   "TIMESTAMP",
	NUMBER:      "NUMBER",
	DIFFICULTY:  "DIFFICULTY",
	GASLIMIT:    "GASLIMIT",
	CHAINID:     "CHAINID",
	SELFBALANCE: "SELFBALANCE",
	BASEFEE:     "BASEFEE",

	// Stack, memory, storage
	POP:      "POP",
	MLOAD:    "MLOAD",
	MSTORE:   "MSTORE",
	MSTORE8:  "MSTORE8",
	SLOAD:    "SLOAD",
	SSTORE:   "SSTORE",
	JUMP:     "JUMP",
	JUMPI:    "JUMPI",
	PC:       "PC",
	MSIZE:    "MSIZE",
	GAS:      "GAS",
	JUMPDEST: "JUMPDEST",

	// Push operations
	PUSH1:  "PUSH1",
	PUSH2:  "PUSH2",
	PUSH3:  "PUSH3",
	PUSH4:  "PUSH4",
	PUSH5:  "PUSH5",
	PUSH6:  "PUSH6",
	PUSH7:  "PUSH7",
	PUSH8:  "PUSH8",
	PUSH9:  "PUSH9",
	PUSH10: "PUSH10",
	PUSH11: "PUSH11",
	PUSH12: "PUSH12",
	PUSH13: "PUSH13",
	PUSH14: "PUSH14",
	PUSH15: "PUSH15",
	PUSH16: "PUSH16",
	PUSH17: "PUSH17",
	PUSH18: "PUSH18",
	PUSH19: "PUSH19",
	PUSH20: "PUSH20",
	PUSH21: "PUSH21",
	PUSH22: "PUSH22",
	PUSH23: "PUSH23",
	PUSH24: "PUSH24",
	PUSH25: "PUSH25",
	PUSH26: "PUSH26",
	PUSH27: "PUSH27",
	PUSH28: "PUSH28",
	PUSH29: "PUSH29",
	PUSH30: "PUSH30",
	PUSH31: "PUSH31",
	PUSH32: "PUSH32",

	// Dup operations
	DUP1:  "DUP1",
	DUP2:  "DUP2",
	DUP3:  "DUP3",
	DUP4:  "DUP4",
	DUP5:  "DUP5",
	DUP6:  "DUP6",
	DUP7:  "DUP7",
	DUP8:  "DUP8",
	DUP9:  "DUP9",
	DUP10: "DUP10",
	DUP11: "DUP11",
	DUP12: "DUP12",
	DUP13: "DUP13",
	DUP14: "DUP14",
	DUP15: "DUP15",
	DUP16: "DUP16",

	// Swap operations
	SWAP1:  "SWAP1",
	SWAP2:  "SWAP2",
	SWAP3:  "SWAP3",
	SWAP4:  "SWAP4",
	SWAP5:  "SWAP5",
	SWAP6:  "SWAP6",
	SWAP7:  "SWAP7",
	SWAP8:  "SWAP8",
	SWAP9:  "SWAP9",
	SWAP10: "SWAP10",
	SWAP11: "SWAP11",
	SWAP12: "SWAP12",
	SWAP13: "SWAP13",
	SWAP14: "SWAP14",
	SWAP15: "SWAP15",
	SWAP16: "SWAP16",

	// Log operations
	LOG0: "LOG0",
	LOG1: "LOG1",
	LOG2: "LOG2",
	LOG3: "LOG3",
	LOG4: "LOG4",

	// System operations
	CREATE:       "CREATE",
	CALL:         "CALL",
	CALLCODE:     "CALLCODE",
	RETURN:       "RETURN",
	DELEGATECALL: "DELEGATECALL",
	CREATE2:      "CREATE2",
	STATICCALL:   "STATICCALL",
	REVERT:       "REVERT",
	INVALID:      "INVALID",
	SELFDESTRUCT: "SELFDESTRUCT",
}

// IsPushOpcode returns true if the opcode is a PUSH instruction (PUSH1-PUSH32).
func IsPushOpcode(op byte) bool {
	return op >= PUSH1 && op <= PUSH32
}

// PushSize returns the number of bytes pushed by a PUSH opcode.
// Returns 0 if the opcode is not a PUSH instruction.
func PushSize(op byte) int {
	if !IsPushOpcode(op) {
		return 0
	}
	return int(op - PUSH1 + 1)
}

// IsDupOpcode returns true if the opcode is a DUP instruction (DUP1-DUP16).
func IsDupOpcode(op byte) bool {
	return op >= DUP1 && op <= DUP16
}

// IsSwapOpcode returns true if the opcode is a SWAP instruction (SWAP1-SWAP16).
func IsSwapOpcode(op byte) bool {
	return op >= SWAP1 && op <= SWAP16
}

// IsLogOpcode returns true if the opcode is a LOG instruction (LOG0-LOG4).
func IsLogOpcode(op byte) bool {
	return op >= LOG0 && op <= LOG4
}

// IsCallOpcode returns true if the opcode is a CALL variant
// (CALL, CALLCODE, DELEGATECALL, or STATICCALL).
func IsCallOpcode(op byte) bool {
	return op == CALL || op == CALLCODE || op == DELEGATECALL || op == STATICCALL
}

// IsCreateOpcode returns true if the opcode is CREATE or CREATE2.
func IsCreateOpcode(op byte) bool {
	return op == CREATE || op == CREATE2
}

// IsTerminalOpcode returns true if the opcode terminates execution
// (STOP, RETURN, REVERT, INVALID, or SELFDESTRUCT).
func IsTerminalOpcode(op byte) bool {
	return op == STOP || op == RETURN || op == REVERT || op == INVALID || op == SELFDESTRUCT
}

// GetOpcodeName returns the human-readable name for an opcode.
// Returns "UNKNOWN" for unrecognized opcodes.
func GetOpcodeName(op byte) string {
	if name, ok := OpcodeNames[op]; ok {
		return name
	}
	return "UNKNOWN"
}
