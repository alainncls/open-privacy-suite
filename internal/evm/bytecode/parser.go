package bytecode

import (
	"encoding/hex"
	"errors"
	"strings"
)

var (
	// ErrInvalidHex is returned when bytecode contains invalid hex characters.
	ErrInvalidHex = errors.New("invalid hex bytecode")
)

// Opcode represents a parsed EVM opcode with its position and arguments.
type Opcode struct {
	Code   byte   // The opcode byte
	Name   string // Human-readable name
	Offset uint64 // Position in bytecode
	Args   []byte // Arguments (for PUSH instructions)
}

// Bytecode represents parsed EVM bytecode.
type Bytecode struct {
	Raw     []byte   // Original bytecode
	Opcodes []Opcode // Parsed opcodes
}

// Parse parses EVM bytecode into a list of opcodes.
// Empty bytecode returns a valid Bytecode with no opcodes.
func Parse(bytecode []byte) (*Bytecode, error) {
	if len(bytecode) == 0 {
		return &Bytecode{Raw: bytecode, Opcodes: nil}, nil
	}

	var opcodes []Opcode
	i := uint64(0)

	for i < uint64(len(bytecode)) {
		op := bytecode[i]
		name := GetOpcodeName(op)

		opcode := Opcode{
			Code:   op,
			Name:   name,
			Offset: i,
		}

		if IsPushOpcode(op) {
			pushSize := PushSize(op)
			end := i + 1 + uint64(pushSize)
			if end > uint64(len(bytecode)) {
				// Truncated PUSH - bytecode ends mid-instruction
				opcode.Args = bytecode[i+1:]
				opcodes = append(opcodes, opcode)
				break
			}
			opcode.Args = bytecode[i+1 : end]
			i = end
		} else {
			i++
		}

		opcodes = append(opcodes, opcode)
	}

	return &Bytecode{Raw: bytecode, Opcodes: opcodes}, nil
}

// ParseHex parses hex-encoded bytecode (with or without 0x prefix).
func ParseHex(hexStr string) (*Bytecode, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return &Bytecode{Raw: nil, Opcodes: nil}, nil
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, ErrInvalidHex
	}
	return Parse(bytes)
}

// HasOpcode returns true if the bytecode contains the given opcode.
func (b *Bytecode) HasOpcode(op byte) bool {
	for _, o := range b.Opcodes {
		if o.Code == op {
			return true
		}
	}
	return false
}

// FindOpcodes returns all occurrences of the given opcode.
func (b *Bytecode) FindOpcodes(op byte) []Opcode {
	var result []Opcode
	for _, o := range b.Opcodes {
		if o.Code == op {
			result = append(result, o)
		}
	}
	return result
}

// FindCallOpcodes returns all CALL, CALLCODE, DELEGATECALL, and STATICCALL opcodes.
func (b *Bytecode) FindCallOpcodes() []Opcode {
	var result []Opcode
	for _, o := range b.Opcodes {
		if IsCallOpcode(o.Code) {
			result = append(result, o)
		}
	}
	return result
}

// FindCreateOpcodes returns all CREATE and CREATE2 opcodes.
func (b *Bytecode) FindCreateOpcodes() []Opcode {
	var result []Opcode
	for _, o := range b.Opcodes {
		if IsCreateOpcode(o.Code) {
			result = append(result, o)
		}
	}
	return result
}

// FindPushOpcodes returns all PUSH opcodes (PUSH1 through PUSH32).
func (b *Bytecode) FindPushOpcodes() []Opcode {
	var result []Opcode
	for _, o := range b.Opcodes {
		if IsPushOpcode(o.Code) {
			result = append(result, o)
		}
	}
	return result
}

// OpcodeCount returns the total number of opcodes in the bytecode.
func (b *Bytecode) OpcodeCount() int {
	return len(b.Opcodes)
}

// IsEmpty returns true if the bytecode is empty or contains no opcodes.
func (b *Bytecode) IsEmpty() bool {
	return len(b.Opcodes) == 0
}

// GetOpcodeAt returns the opcode at the given byte offset, or nil if not found.
func (b *Bytecode) GetOpcodeAt(offset uint64) *Opcode {
	for i := range b.Opcodes {
		if b.Opcodes[i].Offset == offset {
			return &b.Opcodes[i]
		}
	}
	return nil
}
