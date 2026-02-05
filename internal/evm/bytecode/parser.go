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

// StripCBORMetadata removes Solidity's CBOR-encoded metadata from bytecode.
// Solidity appends metadata containing compiler info, source hash, etc.
// The metadata format is:
//   - CBOR-encoded data (starts with 0xa2 for map with 2 elements)
//   - 2-byte length indicator at the very end (big-endian)
//
// This function handles two cases:
// 1. Standard case: CBOR metadata at the end of bytecode
// 2. Constructor args case: CBOR metadata followed by constructor arguments
//    (e.g., when deploying proxies with initialization data)
//
// This is important for bytecode analysis because the metadata is data, not code,
// and may contain bytes that coincidentally match opcode values (like 0x73 = PUSH20
// which is also 's' in "solc").
func StripCBORMetadata(bytecode []byte) []byte {
	if len(bytecode) < 2 {
		return bytecode
	}

	// First, try the standard case: CBOR at the end
	if result := stripCBORFromEnd(bytecode); len(result) < len(bytecode) {
		return result
	}

	// If CBOR wasn't at the end, scan for it in the bytecode.
	// This handles the case where constructor arguments are appended after CBOR.
	// We look for the pattern: [CBOR map marker][...content with "solc"/"ipfs"...][2-byte length]
	return stripEmbeddedCBOR(bytecode)
}

// stripCBORFromEnd attempts to strip CBOR metadata from the end of bytecode.
// Returns the original bytecode if no valid CBOR metadata is found at the end.
func stripCBORFromEnd(bytecode []byte) []byte {
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
	metadataStart := len(bytecode) - metadataLen - 2
	if metadataStart < 0 {
		return bytecode
	}

	if !isValidCBORMetadata(bytecode, metadataStart, len(bytecode)-2) {
		return bytecode
	}

	// Strip the metadata and return just the executable code
	return bytecode[:metadataStart]
}

// stripEmbeddedCBOR finds and removes CBOR metadata that's embedded in the bytecode
// (i.e., when constructor arguments are appended after the CBOR metadata).
func stripEmbeddedCBOR(bytecode []byte) []byte {
	// Scan for CBOR map markers followed by valid CBOR metadata
	// We scan backwards since CBOR is typically near the end, before any constructor args
	minCBORSize := 30 // Minimum reasonable CBOR metadata size

	for i := len(bytecode) - minCBORSize; i >= 0; i-- {
		// Look for CBOR map markers
		if bytecode[i] != 0xa1 && bytecode[i] != 0xa2 && bytecode[i] != 0xa3 {
			continue
		}

		// Try to find the end of this CBOR section by looking for the length indicator
		// The length indicator is 2 bytes at the end of the CBOR section
		// We scan forward from the marker to find valid CBOR content
		for j := i + minCBORSize; j < len(bytecode)-1; j++ {
			// Check if bytes at j and j+1 could be a valid length indicator
			potentialLen := int(bytecode[j])<<8 | int(bytecode[j+1])

			// Check if this length would point back to our marker
			if potentialLen > 0 && potentialLen < 1000 {
				expectedStart := j - potentialLen
				if expectedStart == i {
					// Validate this is actually CBOR metadata
					if isValidCBORMetadata(bytecode, i, j) {
						// Found valid CBOR metadata - remove it
						// Keep bytes before CBOR and bytes after CBOR+length
						result := make([]byte, 0, len(bytecode)-(j+2-i))
						result = append(result, bytecode[:i]...)
						result = append(result, bytecode[j+2:]...)
						return result
					}
				}
			}
		}
	}

	return bytecode
}

// isValidCBORMetadata checks if the section from start to end looks like valid CBOR metadata.
func isValidCBORMetadata(bytecode []byte, start, end int) bool {
	if start < 0 || end > len(bytecode) || start >= end {
		return false
	}

	cborMarker := bytecode[start]
	if cborMarker != 0xa2 && cborMarker != 0xa1 && cborMarker != 0xa3 {
		return false
	}

	// Check for known CBOR keys in Solidity metadata
	section := bytecode[start:end]
	if len(section) < 4 {
		return false
	}

	for i := 0; i < len(section)-4; i++ {
		// Check for "ipfs" (0x69706673)
		if section[i] == 0x69 && section[i+1] == 0x70 &&
			section[i+2] == 0x66 && section[i+3] == 0x73 {
			return true
		}
		// Check for "solc" (0x736f6c63)
		if section[i] == 0x73 && section[i+1] == 0x6f &&
			section[i+2] == 0x6c && section[i+3] == 0x63 {
			return true
		}
		// Check for "bzzr" (0x627a7a72)
		if section[i] == 0x62 && section[i+1] == 0x7a &&
			section[i+2] == 0x7a && section[i+3] == 0x72 {
			return true
		}
	}

	return false
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
