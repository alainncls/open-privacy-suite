package compliance

import (
	"encoding/hex"
	"math/big"
	"strings"
)

// ERC-20 function selectors.
const (
	SelectorTransfer     = "0xa9059cbb" // transfer(address,uint256)
	SelectorTransferFrom = "0x23b872dd" // transferFrom(address,address,uint256)
)

// TransferInfo describes a detected value transfer.
type TransferInfo struct {
	Type         TransferType
	TokenAddress *string  // nil for native ETH
	FromAddress  string   // sender
	ToAddress    string   // recipient
	AmountWei    *big.Int // transfer amount in smallest unit
}

// DetectTransfer analyzes decoded transaction fields and returns transfer info.
// Returns nil if the transaction is not a value transfer.
// Parameters are hex strings as decoded from the transaction (from/to are 0x-prefixed addresses,
// data is 0x-prefixed calldata hex, value is 0x-prefixed hex amount or empty).
func DetectTransfer(from, to, data, value string) *TransferInfo {
	parsedValue := parseHexValue(value)

	// Native ETH transfer: no calldata and value > 0
	if (data == "" || data == "0x") && parsedValue != nil && parsedValue.Sign() > 0 {
		return &TransferInfo{
			Type:        TransferTypeETH,
			FromAddress: from,
			ToAddress:   to,
			AmountWei:   parsedValue,
		}
	}

	// Check for ERC-20 selectors (need at least "0x" + 8 hex chars = 10 chars)
	if len(data) < 10 {
		return nil
	}

	selector := strings.ToLower(data[:10])
	dataBytes, err := hexToBytes(data)
	if err != nil {
		return nil
	}

	switch selector {
	case SelectorTransfer:
		// transfer(address,uint256)
		// ABI: 4-byte selector + 32-byte address + 32-byte uint256 = 68 bytes minimum
		if len(dataBytes) < 68 {
			return nil
		}
		// Address is in bytes 4-36, but only the last 20 bytes are the actual address (bytes 16-36)
		recipientBytes := dataBytes[16:36]
		recipient := "0x" + hex.EncodeToString(recipientBytes)

		// Amount is in bytes 36-68
		amount := new(big.Int).SetBytes(dataBytes[36:68])

		tokenAddr := strings.ToLower(to)
		return &TransferInfo{
			Type:         TransferTypeERC20,
			TokenAddress: &tokenAddr,
			FromAddress:  from,
			ToAddress:    recipient,
			AmountWei:    amount,
		}

	case SelectorTransferFrom:
		// transferFrom(address,address,uint256)
		// ABI: 4-byte selector + 32-byte from + 32-byte to + 32-byte uint256 = 100 bytes minimum
		if len(dataBytes) < 100 {
			return nil
		}
		// From address: bytes 4-36, actual address in bytes 16-36
		senderBytes := dataBytes[16:36]
		sender := "0x" + hex.EncodeToString(senderBytes)

		// To address: bytes 36-68, actual address in bytes 48-68
		recipientBytes := dataBytes[48:68]
		recipient := "0x" + hex.EncodeToString(recipientBytes)

		// Amount: bytes 68-100
		amount := new(big.Int).SetBytes(dataBytes[68:100])

		tokenAddr := strings.ToLower(to)
		return &TransferInfo{
			Type:         TransferTypeERC20,
			TokenAddress: &tokenAddr,
			FromAddress:  sender,
			ToAddress:    recipient,
			AmountWei:    amount,
		}
	}

	return nil
}

// hexToBytes decodes a hex string (with optional "0x" prefix) to bytes.
func hexToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")
	return hex.DecodeString(hexStr)
}

// parseHexValue parses a hex-encoded value string to a *big.Int.
// Returns nil if the input is empty, "0x", or "0x0".
func parseHexValue(hexValue string) *big.Int {
	if hexValue == "" || hexValue == "0x" || hexValue == "0X" || hexValue == "0x0" || hexValue == "0X0" {
		return nil
	}

	cleaned := strings.TrimPrefix(hexValue, "0x")
	cleaned = strings.TrimPrefix(cleaned, "0X")

	val, ok := new(big.Int).SetString(cleaned, 16)
	if !ok {
		return nil
	}
	return val
}
