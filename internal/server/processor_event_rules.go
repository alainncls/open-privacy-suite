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

// buildLogVisibilityContext builds a LogVisibilityContext for the given response.
// It extracts tx hashes from the response body, batch-queries logVisibleTo rules,
// and returns a context the filter can use. Returns nil if the logVisibleTo
// feature is not configured or if no rules are found.
func (p *JSONRPCProcessor) buildLogVisibilityContext(ctx context.Context, userDID string, responseBody []byte) *rbac.LogVisibilityContext {
	if p.logVisibilityStore == nil || userDID == "" {
		return nil
	}

	txHashes := extractTxHashesFromResponse(responseBody)
	if len(txHashes) == 0 {
		return nil
	}

	visibility, err := p.logVisibilityStore.GetBatchTxLogVisibility(ctx, txHashes)
	if err != nil {
		slog.Warn("failed to query logVisibleTo rules", "error", err)
		return nil
	}
	if len(visibility) == 0 {
		return nil
	}

	return &rbac.LogVisibilityContext{
		ViewerDID:    userDID,
		TxVisibility: visibility,
	}
}

// extractTxHashesFromResponse extracts unique transaction hashes from a JSON-RPC
// response body. Works for both eth_getLogs (array of logs) and
// eth_getTransactionReceipt (single receipt with transactionHash + logs).
func extractTxHashesFromResponse(responseBody []byte) []string {
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Result == nil {
		return nil
	}

	seen := make(map[string]bool)

	// Try as array of logs (eth_getLogs response).
	var logs []struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(resp.Result, &logs); err == nil && len(logs) > 0 {
		for _, log := range logs {
			h := strings.ToLower(log.TransactionHash)
			if h != "" && !seen[h] {
				seen[h] = true
			}
		}
	} else {
		// Try as a single receipt (eth_getTransactionReceipt response).
		var receipt struct {
			TransactionHash string `json:"transactionHash"`
			Logs            []struct {
				TransactionHash string `json:"transactionHash"`
			} `json:"logs"`
		}
		if err := json.Unmarshal(resp.Result, &receipt); err == nil {
			h := strings.ToLower(receipt.TransactionHash)
			if h != "" {
				seen[h] = true
			}
			for _, log := range receipt.Logs {
				lh := strings.ToLower(log.TransactionHash)
				if lh != "" && !seen[lh] {
					seen[lh] = true
				}
			}
		}
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
