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
	p.cache[addr] = contract.ABI
	return contract.ABI
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
func FilterLogsWithEventRules(
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	var rawLogs []json.RawMessage
	if err := json.Unmarshal(raw, &rawLogs); err != nil {
		return responseBody
	}

	// Single-pass: FilterEventLogs handles both event-rule and default
	// address-based filtering depending on whether EventRules is configured.
	finalLogs := rbac.FilterEventLogs(rawLogs, perms, userAddresses, abiProvider)

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
func FilterReceiptLogsWithEventRules(
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody
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
		return responseBody
	}

	addrSet := addrSetFromLinked(userAddresses)
	from := strings.ToLower(receipt.From)
	to := strings.ToLower(receipt.To)

	if addrSet[from] || (to != "" && addrSet[to]) {
		id := rpcResponseID(responseBody)

		// Single-pass: applyEventRulesToReceipt calls FilterEventLogs which
		// handles both event-rule and default address-based filtering.
		result := applyEventRulesToReceipt(raw, perms, userAddresses, abiProvider)

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
) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rawReceipt, &m); err != nil {
		return rawReceipt
	}

	rawLogs, ok := m["logs"]
	if !ok {
		return rawReceipt
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(rawLogs, &arr); err != nil {
		return rawReceipt
	}

	filtered := rbac.FilterEventLogs(arr, perms, userAddresses, abiProvider)

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
		return rawReceipt
	}
	return out
}

