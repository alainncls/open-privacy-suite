package audit

import "encoding/json"

// RedactParams returns a JSON representation of request parameters with sensitive data redacted.
// Redaction strategy by method:
//   - eth_sendRawTransaction: truncate raw tx hex to 20 chars
//   - eth_sendTransaction: keep from/to/value/gas, truncate data to 10 chars
//   - eth_call, eth_estimateGas: keep from/to/value, truncate data to 10 chars
//   - All other methods: params pass through unmodified (see AUDIT_LOG_PARAMS docs)
//
// WARNING: enabling AUDIT_LOG_PARAMS logs params for methods not listed above verbatim.
// Ensure you understand what data those methods expose before enabling in production.
func RedactParams(method string, params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	switch method {
	case "eth_sendRawTransaction":
		return redactSendRawTransaction(params)
	case "eth_sendTransaction":
		return redactSendTransaction(params)
	case "eth_call", "eth_estimateGas":
		return redactCallLike(params)
	default:
		// Intentional pass-through: unknown methods are logged verbatim.
		// WARNING: this means sensitive arguments for unlisted methods will appear
		// in audit logs. Operators should review which methods are enabled before
		// turning on AUDIT_LOG_PARAMS in production.
		out, err := json.Marshal(params)
		if err != nil {
			return nil
		}
		return out
	}
}

// redactSendRawTransaction truncates the raw transaction hex to 20 characters.
func redactSendRawTransaction(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	redacted := make([]any, len(params))
	copy(redacted, params)

	if raw, ok := redacted[0].(string); ok {
		redacted[0] = truncate(raw, 20)
	}

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// redactSendTransaction keeps from/to/value/gas and truncates data/input.
func redactSendTransaction(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	obj, ok := params[0].(map[string]any)
	if !ok {
		out, _ := json.Marshal(params)
		return out
	}

	safe := map[string]any{}
	for _, key := range []string{"from", "to", "value", "gas", "gasPrice"} {
		if v, exists := obj[key]; exists {
			safe[key] = v
		}
	}
	truncateDataField(obj, safe)

	redacted := make([]any, len(params))
	copy(redacted, params)
	redacted[0] = safe

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// redactCallLike handles eth_call and eth_estimateGas: keep from/to/value, truncate data/input.
func redactCallLike(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	obj, ok := params[0].(map[string]any)
	if !ok {
		out, _ := json.Marshal(params)
		return out
	}

	safe := map[string]any{}
	for _, key := range []string{"from", "to", "value", "gas", "gasPrice"} {
		if v, exists := obj[key]; exists {
			safe[key] = v
		}
	}
	truncateDataField(obj, safe)

	// Preserve additional positional params (e.g., block number for eth_call).
	redacted := make([]any, len(params))
	copy(redacted, params)
	redacted[0] = safe

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// truncateDataField copies the "data" or "input" field from src to dst, truncated to 10 chars.
func truncateDataField(src, dst map[string]any) {
	for _, key := range []string{"data", "input"} {
		if v, exists := src[key]; exists {
			if s, ok := v.(string); ok {
				dst[key] = truncate(s, 10)
			}
		}
	}
}

// truncate shortens s to maxLen characters and appends "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
