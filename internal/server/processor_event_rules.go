package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"privacy-proxy/internal/rbac"
)

// resolvePermsForFilter resolves the user's effective permissions across ALL
// their orgs for response filtering. This is necessary because receipts and
// logs may reference contracts from any org the user belongs to — the RBAC
// access check resolves a single org from the request target, but receipt
// logs can contain events from contracts in different orgs.
func (p *JSONRPCProcessor) resolvePermsForFilter(ctx context.Context, result *rbac.AccessCheckResult) *rbac.EffectivePermissions {
	if result == nil || result.UserID == "" {
		return nil
	}

	// Get all org IDs the user belongs to
	orgIDs, err := p.rbacAccessCtrl.GetUserOrgIDs(ctx, result.UserID)
	if err != nil || len(orgIDs) == 0 {
		return nil
	}

	// Resolve permissions for each org and merge contract access
	var merged *rbac.EffectivePermissions
	for _, orgID := range orgIDs {
		perms, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, result.UserID, orgID)
		if err != nil {
			continue
		}
		if merged == nil {
			merged = perms
			continue
		}
		// Merge ContractAccess from this org into the merged result
		for addr, ca := range perms.ContractAccess {
			if merged.ContractAccess == nil {
				merged.ContractAccess = make(map[string]rbac.ContractAccess)
			}
			if _, exists := merged.ContractAccess[addr]; !exists {
				merged.ContractAccess[addr] = ca
			}
		}
	}
	return merged
}

// contractABIProvider returns an ABIProvider backed by the RBAC store.
func (p *JSONRPCProcessor) contractABIProvider(ctx context.Context) rbac.ABIProvider {
	return newStoreABIProvider(ctx, p.rbacAccessCtrl.Store())
}

// isResponseTxVisibleTo checks if the transaction in the response body has been
// shared with the viewer via the visibleTo param. Extracts the tx hash from the
// response and checks tx_visible_to.
func (p *JSONRPCProcessor) isResponseTxVisibleTo(ctx context.Context, viewerDID string, responseBody []byte) bool {
	if p.txVisibilityStore == nil || viewerDID == "" {
		return false
	}
	txHashes := extractTxHashesFromResponse(responseBody)
	if len(txHashes) == 0 {
		return false
	}
	visibility, err := p.txVisibilityStore.GetBatchTxVisibility(ctx, txHashes)
	if err != nil || len(visibility) == 0 {
		return false
	}
	for _, dids := range visibility {
		for _, did := range dids {
			if strings.EqualFold(did, viewerDID) {
				return true
			}
		}
	}
	return false
}

// isNullResult checks if a JSON-RPC response has a null result.
func isNullResult(body []byte) bool {
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return false
	}
	return resp.Result == nil || string(*resp.Result) == "null"
}

// buildTxVisibilityContext builds a TxVisibilityContext for the given response.
// It extracts tx hashes from the response body, batch-queries visibleTo rules,
// and returns a context the filter can use. Returns nil if the visibleTo
// feature is not configured or if no rules are found.
func (p *JSONRPCProcessor) buildTxVisibilityContext(ctx context.Context, userDID string, responseBody []byte) *rbac.TxVisibilityContext {
	if p.txVisibilityStore == nil || userDID == "" {
		return nil
	}

	txHashes := extractTxHashesFromResponse(responseBody)
	if len(txHashes) == 0 {
		return nil
	}

	visibility, err := p.txVisibilityStore.GetBatchTxVisibility(ctx, txHashes)
	if err != nil {
		slog.Warn("failed to query visibleTo rules", "error", err)
		return nil
	}
	if len(visibility) == 0 {
		return nil
	}

	return &rbac.TxVisibilityContext{
		ViewerDID:    userDID,
		TxVisibility: visibility,
	}
}

// extractTxHashesFromResponse extracts unique transaction hashes from a JSON-RPC
// response body. Handles three shapes:
//
//   - eth_getLogs — array of log objects (hash field: "transactionHash")
//   - eth_getTransactionReceipt — single receipt (hash field: "transactionHash")
//   - eth_getTransactionByHash / ...ByBlockHashAndIndex / ...ByBlockNumberAndIndex —
//     single transaction object (hash field: "hash", per the Ethereum JSON-RPC spec)
//
// All three shapes are attempted independently because Go's json.Unmarshal silently
// tolerates missing fields — e.g. unmarshaling a tx body into the receipt struct
// succeeds but produces an empty TransactionHash, so the tx-object branch is
// required as an additional attempt (not a fallback). The seen map dedupes.
func extractTxHashesFromResponse(responseBody []byte) []string {
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Result == nil {
		return nil
	}

	seen := make(map[string]bool)
	addHash := func(h string) {
		h = strings.ToLower(h)
		if h != "" && !seen[h] {
			seen[h] = true
		}
	}

	// Try as array of logs (eth_getLogs response).
	var logs []struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(resp.Result, &logs); err == nil {
		for _, log := range logs {
			addHash(log.TransactionHash)
		}
	}

	// Try as a single receipt (eth_getTransactionReceipt response).
	var receipt struct {
		TransactionHash string `json:"transactionHash"`
		Logs            []struct {
			TransactionHash string `json:"transactionHash"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(resp.Result, &receipt); err == nil {
		addHash(receipt.TransactionHash)
		for _, log := range receipt.Logs {
			addHash(log.TransactionHash)
		}
	}

	// Try as a single transaction object (eth_getTransactionByHash et al.).
	// Transaction objects use "hash", not "transactionHash" — this branch is why
	// the others can't be an if/else chain.
	var tx struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(resp.Result, &tx); err == nil {
		addHash(tx.Hash)
	}

	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for h := range seen {
		result = append(result, h)
	}
	return result
}
