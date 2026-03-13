package explorer

import (
	"context"
	"strings"
)

// VisibilityMap maps an address (lowercase) to its resolved visibility level
type VisibilityMap map[string]VisibilityLevel

// RedactionEngine handles the bulk redaction of explorer data based on user grants
type RedactionEngine struct {
	store *Store
	db    Database // The main privacy proxy DB for RBAC checks
}

// Database interface for the methods RedactionEngine needs from the main DB
type Database interface {
	GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (VisibilityMap, error)
}

func NewRedactionEngine(store *Store, db Database) *RedactionEngine {
	return &RedactionEngine{
		store: store,
		db:    db,
	}
}

// extractUniqueAddresses gets all unique from/to addresses from a list of transactions
func extractUniqueAddresses(txs []Transaction) []string {
	addrMap := make(map[string]bool)
	for _, tx := range txs {
		if tx.From != "" {
			addrMap[strings.ToLower(tx.From)] = true
		}
		if tx.To != nil && *tx.To != "" {
			addrMap[strings.ToLower(*tx.To)] = true
		}
	}

	var addrs []string
	for addr := range addrMap {
		addrs = append(addrs, addr)
	}
	return addrs
}

// RedactTransactions applies privacy rules to a list of transactions
func (r *RedactionEngine) RedactTransactions(ctx context.Context, txs []Transaction, viewerDID string) ([]Transaction, error) {
	if len(txs) == 0 {
		return txs, nil
	}

	// 1. Extract unique addresses
	uniqueAddrs := extractUniqueAddresses(txs)

	// 2. Get batch visibility
	visibilityMap, err := r.db.GetBatchVisibility(ctx, viewerDID, uniqueAddrs)
	if err != nil {
		return nil, err
	}

	// 3. Apply redactions
	var redactedTxs []Transaction
	for _, tx := range txs {
		redactedTx := tx

		fromLevel := VisibilityFull
		if tx.From != "" {
			fromLevel = visibilityMap[strings.ToLower(tx.From)]
			redactedTx.From = r.applyRedaction(tx.From, fromLevel)
		}

		toLevel := VisibilityFull
		if tx.To != nil && *tx.To != "" {
			toLevel = visibilityMap[strings.ToLower(*tx.To)]
			redacted := r.applyRedaction(*tx.To, toLevel)
			redactedTx.To = &redacted
		}

		// If either participant is fully hidden, drop the transaction
		if fromLevel == VisibilityHidden || toLevel == VisibilityHidden {
			continue
		}

		// If either participant is redacted, strip the transaction data
		if fromLevel == VisibilityRedacted || toLevel == VisibilityRedacted {
			redactedTx.Value = JSONString("")
			redactedTx.InputData = ""
			redactedTx.Error = nil
			redactedTx.RevertReason = nil
		}

		redactedTxs = append(redactedTxs, redactedTx)
	}

	return redactedTxs, nil
}

// RedactTransfers applies privacy rules to a list of token transfers
func (r *RedactionEngine) RedactTransfers(ctx context.Context, transfers []TokenTransfer, viewerDID string) ([]TokenTransfer, error) {
	if len(transfers) == 0 {
		return transfers, nil
	}

	addrMap := make(map[string]bool)
	for _, t := range transfers {
		if t.From != "" {
			addrMap[strings.ToLower(t.From)] = true
		}
		if t.To != "" {
			addrMap[strings.ToLower(t.To)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	var result []TokenTransfer
	for _, t := range transfers {
		fromLevel := visMap[strings.ToLower(t.From)]
		toLevel := visMap[strings.ToLower(t.To)]

		if fromLevel == VisibilityHidden || toLevel == VisibilityHidden {
			continue
		}

		redacted := t
		redacted.From = r.applyRedaction(t.From, fromLevel)
		redacted.To = r.applyRedaction(t.To, toLevel)
		if fromLevel == VisibilityRedacted || toLevel == VisibilityRedacted {
			redacted.Value = JSONString("")
		}

		result = append(result, redacted)
	}
	return result, nil
}

// RedactInternalTransactions applies privacy rules to a list of internal transactions
func (r *RedactionEngine) RedactInternalTransactions(ctx context.Context, itxs []InternalTransaction, viewerDID string) ([]InternalTransaction, error) {
	if len(itxs) == 0 {
		return itxs, nil
	}

	addrMap := make(map[string]bool)
	for _, t := range itxs {
		if t.From != "" {
			addrMap[strings.ToLower(t.From)] = true
		}
		if t.To != nil && *t.To != "" {
			addrMap[strings.ToLower(*t.To)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	var result []InternalTransaction
	for _, t := range itxs {
		fromLevel := visMap[strings.ToLower(t.From)]
		toLevel := VisibilityFull
		if t.To != nil && *t.To != "" {
			toLevel = visMap[strings.ToLower(*t.To)]
		}

		if fromLevel == VisibilityHidden || toLevel == VisibilityHidden {
			continue
		}

		redacted := t
		redacted.From = r.applyRedaction(t.From, fromLevel)
		if t.To != nil && *t.To != "" {
			r2 := r.applyRedaction(*t.To, toLevel)
			redacted.To = &r2
		}
		if fromLevel == VisibilityRedacted || toLevel == VisibilityRedacted {
			redacted.Value = JSONString("")
			redacted.Input = nil
			redacted.Output = nil
		}

		result = append(result, redacted)
	}
	return result, nil
}

// RedactLogs applies privacy rules to event logs.
// The log Address field is the contract that emitted the event.
// Hidden contracts are dropped; pseudonymous/redacted contracts have their address masked
// and topic/data stripped to prevent correlation.
func (r *RedactionEngine) RedactLogs(ctx context.Context, logs []Log, viewerDID string) ([]Log, error) {
	if len(logs) == 0 {
		return logs, nil
	}

	addrMap := make(map[string]bool)
	for _, l := range logs {
		if l.Address != "" {
			addrMap[strings.ToLower(l.Address)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	var result []Log
	for _, l := range logs {
		level := visMap[strings.ToLower(l.Address)]

		if level == VisibilityHidden {
			continue
		}

		redacted := l
		redacted.Address = r.applyRedaction(l.Address, level)
		if level == VisibilityRedacted {
			redacted.Topic0 = nil
			redacted.Topic1 = nil
			redacted.Topic2 = nil
			redacted.Topic3 = nil
			redacted.Data = ""
		}

		result = append(result, redacted)
	}
	return result, nil
}

// RedactAddress redacts a single address based on visibility for the viewer.
func (r *RedactionEngine) RedactAddress(ctx context.Context, address string, viewerDID string) (string, error) {
	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, []string{strings.ToLower(address)})
	if err != nil {
		return "[REDACTED]", err
	}
	level := visMap[strings.ToLower(address)]
	return r.applyRedaction(address, level), nil
}

// RedactTokenHolders applies privacy rules to token holder list.
// Holders with hidden addresses are dropped; others have their address masked.
func (r *RedactionEngine) RedactTokenHolders(ctx context.Context, holders []TokenHolder, viewerDID string) ([]TokenHolder, error) {
	if len(holders) == 0 {
		return holders, nil
	}

	addrMap := make(map[string]bool)
	for _, h := range holders {
		if h.Address != "" {
			addrMap[strings.ToLower(h.Address)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	var result []TokenHolder
	for _, h := range holders {
		level := visMap[strings.ToLower(h.Address)]
		if level == VisibilityHidden {
			continue
		}
		h.Address = r.applyRedaction(h.Address, level)
		result = append(result, h)
	}
	return result, nil
}

// applyRedaction modifies an address string based on its visibility level
func (r *RedactionEngine) applyRedaction(address string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		return address
	case VisibilityPseudonymous:
		return GeneratePseudonym(address)
	case VisibilityRedacted:
		return "[PRIVATE]"
	case VisibilityHidden:
		return "[PRIVATE]"
	default:
		return "[PRIVATE]" // Fail safe
	}
}
