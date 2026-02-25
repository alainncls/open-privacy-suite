package audit

import "encoding/json"

// RedactParams returns a JSON representation of request parameters with sensitive data redacted.
// The redaction strategy depends on the JSON-RPC method:
//   - eth_sendRawTransaction: truncates the raw tx hex to 20 chars
//   - eth_sendTransaction: keeps from/to/value, truncates data to 10 chars
//   - All other methods: params pass through unmodified
func RedactParams(method string, params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	switch method {
	case "eth_sendRawTransaction":
		return redactRawTx(params)
	case "eth_sendTransaction":
		return redactSendTx(params)
	default:
		b, err := json.Marshal(params)
		if err != nil {
			return nil
		}
		return b
	}
}

func redactRawTx(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	rawTx, ok := params[0].(string)
	if !ok {
		return nil
	}

	// Truncate to 20 chars + ellipsis
	if len(rawTx) > 20 {
		rawTx = rawTx[:20] + "..."
	}

	redacted := []any{rawTx}
	b, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return b
}

func redactSendTx(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return nil
	}

	redacted := make(map[string]any)

	// Keep safe fields
	for _, key := range []string{"from", "to", "value", "gas", "gasPrice", "nonce"} {
		if v, exists := txObj[key]; exists {
			redacted[key] = v
		}
	}

	// Truncate data/input fields
	for _, key := range []string{"data", "input"} {
		if v, exists := txObj[key]; exists {
			if s, ok := v.(string); ok && len(s) > 10 {
				redacted[key] = s[:10] + "..."
			} else {
				redacted[key] = v
			}
		}
	}

	result := []any{redacted}
	b, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	return b
}
