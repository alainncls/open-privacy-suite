package server

import (
	"context"
	"encoding/json"
	"strings"

	"privacy-proxy/internal/rbac"
)

// storeABIProvider implements rbac.ABIProvider by looking up contract ABIs
// from the RBAC store. It caches ABIs within a single request to avoid
// repeated DB lookups.
type storeABIProvider struct {
	store rbac.Store
	ctx   context.Context
	cache map[string]string // address -> ABI JSON (empty string if not found)
}

func newStoreABIProvider(ctx context.Context, store rbac.Store) *storeABIProvider {
	return &storeABIProvider{
		store: store,
		ctx:   ctx,
		cache: make(map[string]string),
	}
}

func (p *storeABIProvider) GetContractABI(address string) string {
	addr := strings.ToLower(address)
	if abi, ok := p.cache[addr]; ok {
		return abi
	}
	contract, err := p.store.GetContractByAddressGlobal(p.ctx, addr)
	if err != nil || contract == nil {
		p.cache[addr] = ""
		return ""
	}
	abi := contract.ABI
	// Fall back to built-in ABI if no custom ABI is stored but the contract
	// has a known token type in its metadata.
	if abi == "" && contract.Metadata != nil {
		if tokenType, ok := contract.Metadata["token_type"].(string); ok {
			abi = rbac.GetBuiltInABI(tokenType)
		}
	}
	p.cache[addr] = abi
	return abi
}

// FilterLogsWithEventRules filters an eth_getLogs response using the unified
// event filtering logic in rbac.FilterEventLogs.
//
// When event rules are configured for a contract: allowlist mode — only listed
// topic0s pass (with optional "self" param constraints).
// When no event rules are configured (nil): default address-based filtering —
// log visible only if user's address appears in any topic.
//
// If perms is nil (user/org resolution failed), FilterEventLogs returns empty
// (fail-closed).
// visCtx provides optional per-tx visibleTo data (may be nil).
func FilterLogsWithEventRules(
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
	visCtx *rbac.TxVisibilityContext,
) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		// Fail-closed: unparseable response → return empty logs
		return emptyLogsResponse(responseBody)
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody // RPC error or null result — pass through as-is
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	var rawLogs []json.RawMessage
	if err := json.Unmarshal(raw, &rawLogs); err != nil {
		// Fail-closed: result isn't a JSON array → return empty logs
		return emptyLogsResponse(responseBody)
	}

	// Single-pass: FilterEventLogs handles both event-rule and default
	// address-based filtering depending on whether EventRules is configured.
	finalLogs := rbac.FilterEventLogs(rawLogs, perms, userAddresses, abiProvider, visCtx)

	filteredJSON, err := json.Marshal(finalLogs)
	if err != nil {
		return responseBody
	}

	result := json.RawMessage(filteredJSON)
	out, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  result,
	})
	if err != nil {
		return responseBody
	}
	return out
}

// FilterReceiptLogsWithEventRules filters receipt logs using the unified
// event filtering logic. Participants get their receipt with filtered logs;
// non-participants get null.
// visCtx provides optional per-tx visibleTo data (may be nil).
func FilterReceiptLogsWithEventRules(
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
	visCtx *rbac.TxVisibilityContext,
) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		// Fail-closed: unparseable response → return null result
		id := rpcResponseID(responseBody)
		return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody // RPC error or null result — pass through as-is
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	var receipt struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		// Fail-closed: unparseable receipt → return null
		id := rpcResponseID(responseBody)
		return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
	}

	addrSet := addrSetFromLinked(userAddresses)
	from := strings.ToLower(receipt.From)
	to := strings.ToLower(receipt.To)

	if addrSet[from] || (to != "" && addrSet[to]) {
		id := rpcResponseID(responseBody)

		// Single-pass: applyEventRulesToReceipt calls FilterEventLogs which
		// handles both event-rule and default address-based filtering.
		result := applyEventRulesToReceipt(raw, perms, userAddresses, abiProvider, visCtx)

		if id != "" {
			wrapped, _ := json.Marshal(struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      json.RawMessage `json:"id"`
				Result  json.RawMessage `json:"result"`
			}{
				JSONRPC: "2.0",
				ID:      json.RawMessage(id),
				Result:  result,
			})
			return wrapped
		}
		return result
	}

	// Non-participant: return null.
	id := rpcResponseID(responseBody)
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
}

// applyEventRulesToReceipt extracts logs from a receipt, applies event rule
// filtering, and puts the filtered logs back.
func applyEventRulesToReceipt(
	rawReceipt json.RawMessage,
	perms *rbac.EffectivePermissions,
	userAddresses []string,
	abiProvider rbac.ABIProvider,
	visCtx *rbac.TxVisibilityContext,
) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rawReceipt, &m); err != nil {
		return receiptWithEmptyLogs(rawReceipt) // fail-closed
	}

	rawLogs, ok := m["logs"]
	if !ok {
		return rawReceipt // no logs field — nothing to filter
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(rawLogs, &arr); err != nil {
		return receiptWithEmptyLogs(rawReceipt) // fail-closed
	}

	filtered := rbac.FilterEventLogs(arr, perms, userAddresses, abiProvider, visCtx)

	newLogs, err := json.Marshal(filtered)
	if err != nil {
		return rawReceipt
	}
	m["logs"] = newLogs

	// Zero logsBloom since we modified logs.
	zeroBloom := `"0x` + strings.Repeat("0", 512) + `"`
	m["logsBloom"] = json.RawMessage(zeroBloom)

	out, err := json.Marshal(m)
	if err != nil {
		return receiptWithEmptyLogs(rawReceipt) // fail-closed
	}
	return out
}

// emptyLogsResponse returns a JSON-RPC response with an empty logs array,
// preserving the original response's ID. Used for fail-closed behavior.
func emptyLogsResponse(responseBody []byte) []byte {
	id := rpcResponseID(responseBody)
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":[]}`)
}

// receiptWithEmptyLogs returns a receipt JSON with logs set to [] and
// logsBloom zeroed. Used for fail-closed behavior when log parsing fails.
func receiptWithEmptyLogs(rawReceipt json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rawReceipt, &m); err != nil {
		// Can't even parse the receipt — return as-is (already a failure path)
		return rawReceipt
	}
	m["logs"] = json.RawMessage("[]")
	zeroBloom := `"0x` + strings.Repeat("0", 512) + `"`
	m["logsBloom"] = json.RawMessage(zeroBloom)
	out, err := json.Marshal(m)
	if err != nil {
		return rawReceipt
	}
	return out
}

