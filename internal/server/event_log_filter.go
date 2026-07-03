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
//
// Also implements rbac.DynamicPayloadAllower (M15) — the per-contract
// `events_allow_dynamic_payload` opt-out is read from the same Contract
// row and cached alongside the ABI so the drop gate in FilterEventLogs
// honours operator intent without an extra DB round-trip.
type storeABIProvider struct {
	store               rbac.Store
	ctx                 context.Context
	cache               map[string]string // address -> ABI JSON (empty string if not found)
	dynamicPayloadCache map[string]bool   // address -> events_allow_dynamic_payload
}

func newStoreABIProvider(ctx context.Context, store rbac.Store) *storeABIProvider {
	return &storeABIProvider{
		store:               store,
		ctx:                 ctx,
		cache:               make(map[string]string),
		dynamicPayloadCache: make(map[string]bool),
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
		p.dynamicPayloadCache[addr] = false
		return ""
	}
	abi := rbac.ResolveContractABI(contract)
	p.cache[addr] = abi
	p.dynamicPayloadCache[addr] = contract.EventsAllowDynamicPayload
	return abi
}

// IsEventsAllowDynamicPayload implements rbac.DynamicPayloadAllower
// (M15). Returns the per-contract opt-out flag for the dynamic-payload
// drop gate. Defaults to FALSE (close-by-default) when the contract is
// unknown — same posture as the deny-when-no-ABI gate.
//
// Always calls GetContractABI first to populate the cache so the two
// reads agree on the row. GetContractABI is idempotent and cached, so
// the cost is one DB lookup per address per request.
func (p *storeABIProvider) IsEventsAllowDynamicPayload(address string) bool {
	addr := strings.ToLower(address)
	if _, cached := p.cache[addr]; !cached {
		_ = p.GetContractABI(addr)
	}
	return p.dynamicPayloadCache[addr]
}

// FilterLogsWithEventRules filters an eth_getLogs response using the unified
// event filtering logic in rbac.FilterEventLogs.
//
// When event rules are configured for a contract: allowlist mode — only listed
// topic0s pass (with optional "self" param constraints).
// When no event rules are configured (nil or empty []): deny all — no logs
// pass for that contract.
//
// If perms is nil (user/org resolution failed), FilterEventLogs returns empty
// (fail-closed).
// visCtx provides optional per-tx visibleTo data (may be nil).
//
// isAdminByContract — see rbac.FilterEventLogs for semantics. Map keys
// are lowercased contract addresses; presence with true means the viewer
// has the admin claim in THAT contract's owning org only.
func FilterLogsWithEventRules(
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
	visCtx *rbac.TxVisibilityContext,
	isAdminByContract map[string]bool,
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
	finalLogs := rbac.FilterEventLogs(rawLogs, perms, userAddresses, abiProvider, visCtx, isAdminByContract)

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
// event filtering logic. Participants, visibleTo recipients, and admins
// on the tx's `to` contract get their receipt with event-rule-filtered
// logs; anyone else gets null.
//
// `isAdminOnTo` is an org-scoped pre-computation — the caller must have
// resolved it via JSONRPCProcessor.viewerIsAdminOnResponseTxContract
// (or equivalent), which looks up the contract's owning org and checks
// the viewer's admin claim in THAT org only. This is intentionally not
// derived from `perms` inside the filter — `perms` is merged across
// all orgs the viewer belongs to, and using it directly would rely on
// the global-unique-address DB invariant for correctness. Passing the
// pre-scoped bool keeps the invariant as belt + schema as braces.
//
// visCtx provides optional per-tx visibleTo data (may be nil).
func FilterReceiptLogsWithEventRules(
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
	visCtx *rbac.TxVisibilityContext,
	isAdminByContract map[string]bool,
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

	isParticipant := addrSet[from] || (to != "" && addrSet[to])

	// visibleTo check: if the viewer is in this tx's visibleTo list,
	// treat them as a participant for receipt access purposes.
	isVisibleTo := false
	if !isParticipant && visCtx != nil && visCtx.ViewerDID != "" {
		var txHash struct {
			TransactionHash string `json:"transactionHash"`
		}
		if json.Unmarshal(raw, &txHash) == nil && txHash.TransactionHash != "" {
			hashLower := strings.ToLower(txHash.TransactionHash)
			if dids, ok := visCtx.TxVisibility[hashLower]; ok {
				for _, did := range dids {
					if strings.EqualFold(did, visCtx.ViewerDID) {
						isVisibleTo = true
						break
					}
				}
			}
		}
	}

	// Admin bypass at the envelope level: the viewer has the admin claim
	// in the tx's `to` contract's OWNING org (not merged across orgs).
	// isAdminByContract is pre-computed at the call site via
	// JSONRPCProcessor.viewerAdminContracts; absence in the map (or false
	// value) means no admin claim in the contract's own org. See
	// docs/security/response-filtering:238 for the "admins always see all
	// events" semantics.
	isAdminOnTo := to != "" && isAdminByContract[to]

	if isParticipant || isVisibleTo || isAdminOnTo {
		id := rpcResponseID(responseBody)

		// RD-1162: a participant (from/to) of this tx sees ALL of its logs on
		// contracts they can access — not just logs carrying their address.
		// Inject the tx hash into the participant set so FilterEventLogs admits
		// address-less events (e.g. PaymentCompleted) instead of stripping them
		// (bounded there by contract-grant access). Envelope participation was
		// already established above; here we propagate it to the log filter,
		// closing the "participant enough for the receipt, not for its logs"
		// asymmetry.
		if isParticipant {
			var txMeta struct {
				TransactionHash string `json:"transactionHash"`
			}
			if json.Unmarshal(raw, &txMeta) == nil && txMeta.TransactionHash != "" {
				if visCtx == nil {
					visCtx = &rbac.TxVisibilityContext{}
				}
				if visCtx.ParticipantTxHashes == nil {
					visCtx.ParticipantTxHashes = make(map[string]bool, 1)
				}
				visCtx.ParticipantTxHashes[strings.ToLower(txMeta.TransactionHash)] = true
			}
		}

		// Single-pass: applyEventRulesToReceipt calls FilterEventLogs which
		// handles both event-rule and default address-based filtering.
		// Pass the full per-log admin map so the per-log admin bypass in
		// FilterEventLogs uses the same org-scoped decisions.
		result := applyEventRulesToReceipt(raw, perms, userAddresses, abiProvider, visCtx, isAdminByContract)

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

	// Non-participant and not in visibleTo: return null.
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
	isAdminByContract map[string]bool,
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

	filtered := rbac.FilterEventLogs(arr, perms, userAddresses, abiProvider, visCtx, isAdminByContract)

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
