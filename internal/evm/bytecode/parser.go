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
// NOTE: This parses the raw bytecode without stripping metadata.
// For security analysis, use ParseForAnalysis which strips CBOR metadata.
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

// ParseForAnalysis parses bytecode with CBOR metadata stripped.
// This should be used for security analysis (detecting CREATE/CREATE2, etc.)
// because Solidity's CBOR metadata at the end of contracts is data, not code,
// and may contain byte sequences that look like opcodes but aren't executable.
func ParseForAnalysis(bytecode []byte) (*Bytecode, error) {
	if len(bytecode) == 0 {
		return &Bytecode{Raw: bytecode, Opcodes: nil}, nil
	}

	// Strip CBOR metadata before parsing
	executableCode := StripCBORMetadata(bytecode)
	return Parse(executableCode)
}

// ParseHexForAnalysis parses hex-encoded bytecode for security analysis.
// It strips Solidity's CBOR metadata before parsing.
func ParseHexForAnalysis(hexStr string) (*Bytecode, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return &Bytecode{Raw: nil, Opcodes: nil}, nil
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, ErrInvalidHex
	}
	return ParseForAnalysis(bytes)
}

// StripCBORMetadata removes Solidity's CBOR-encoded metadata from the end of bytecode.
// Solidity appends metadata containing compiler info, source hash, etc.
// The metadata format is:
//   - CBOR-encoded data (starts with 0xa2 for map with 2 elements)
//   - 2-byte length indicator at the very end (big-endian)
//
// This is important for bytecode analysis because the metadata is data, not code,
// and may contain bytes that coincidentally match opcode values (like 0xf0 = CREATE
// or 0xf5 = CREATE2) but are not actual instructions.
func StripCBORMetadata(bytecode []byte) []byte {
	if len(bytecode) < 2 {
		return bytecode
	}

	// The last 2 bytes indicate the metadata length
	metadataLen := int(bytecode[len(bytecode)-2])<<8 | int(bytecode[len(bytecode)-1])

	// Sanity check: metadata length should be reasonable
	// Typical metadata is 50-100 bytes, max reasonable is ~500 bytes
	if metadataLen <= 0 || metadataLen >= 1000 || metadataLen+2 > len(bytecode) {
		return bytecode
	}

	// Check if the metadata starts with a CBOR map marker
	// 0xa2 = map with 2 elements (common for Solidity >= 0.6.0)
	// 0xa1 = map with 1 element (older format)
	metadataStart := len(bytecode) - metadataLen - 2
	if metadataStart < 0 {
		return bytecode
	}

	cborMarker := bytecode[metadataStart]
	if cborMarker != 0xa2 && cborMarker != 0xa1 && cborMarker != 0xa3 {
		return bytecode
	}

	// Additional validation: check for "ipfs" or "bzzr" or "solc" in metadata
	// These are common CBOR keys in Solidity metadata
	metadataSection := bytecode[metadataStart : len(bytecode)-2]
	hasKnownKey := false
	for i := 0; i < len(metadataSection)-4; i++ {
		// Check for "ipfs" (0x69706673)
		if metadataSection[i] == 0x69 && metadataSection[i+1] == 0x70 &&
			metadataSection[i+2] == 0x66 && metadataSection[i+3] == 0x73 {
			hasKnownKey = true
			break
		}
		// Check for "solc" (0x736f6c63)
		if metadataSection[i] == 0x73 && metadataSection[i+1] == 0x6f &&
			metadataSection[i+2] == 0x6c && metadataSection[i+3] == 0x63 {
			hasKnownKey = true
			break
		}
		// Check for "bzzr" (0x627a7a72)
		if metadataSection[i] == 0x62 && metadataSection[i+1] == 0x7a &&
			metadataSection[i+2] == 0x7a && metadataSection[i+3] == 0x72 {
			hasKnownKey = true
			break
		}
	}

	if !hasKnownKey {
		return bytecode
	}

	// Strip the metadata and return just the executable code
	return bytecode[:metadataStart]
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
