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

// FilterLogsWithEventRules filters an eth_getLogs response using both:
//  1. Address-based topic filtering (existing behavior: user's address must appear in a topic)
//  2. Event-rule-based filtering (new: allowlist of events by topic0 with optional "self" param constraints)
//
// If perms is nil or has no event rules for the log's contract, falls back to address-only filtering.
// If perms has event rules, the log must pass both the event rule check AND the address check.
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

	addrSet := addrSetFromLinked(userAddresses)

	// Phase 1: Apply address-based topic filtering (existing behavior).
	addrFiltered := make([]json.RawMessage, 0, len(rawLogs))
	for _, rawLog := range rawLogs {
		var entry struct {
			Topics []string `json:"topics"`
		}
		if err := json.Unmarshal(rawLog, &entry); err != nil {
			continue
		}

		visible := false
		for i := 0; i < len(entry.Topics); i++ {
			if topicMatchesAddress(entry.Topics[i], addrSet) {
				visible = true
				break
			}
		}
		if visible {
			addrFiltered = append(addrFiltered, rawLog)
		}
	}

	// Phase 2: Apply event rule filtering on the address-filtered results.
	var finalLogs []json.RawMessage
	if perms != nil && hasAnyEventRules(perms) {
		finalLogs = rbac.FilterEventLogs(addrFiltered, perms, userAddresses, abiProvider)
	} else {
		finalLogs = addrFiltered
	}

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

// FilterReceiptLogsWithEventRules applies event rule filtering to receipt logs
// in addition to the existing address-based filtering.
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

		// First apply existing address-based receipt log filtering.
		result := filterReceiptLogs(raw, addrSet, "")

		// If event rules exist, apply them to the receipt's logs.
		if perms != nil && hasAnyEventRules(perms) {
			result = applyEventRulesToReceipt(result, perms, userAddresses, abiProvider)
		}

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

// hasAnyEventRules checks if the effective permissions contain any event rules
// for any contract.
func hasAnyEventRules(perms *rbac.EffectivePermissions) bool {
	for _, access := range perms.ContractAccess {
		if access.EventRules != nil {
			return true
		}
	}
	return false
}
