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

// applyRedaction modifies an address string based on its visibility level
func (r *RedactionEngine) applyRedaction(address string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		return address
	case VisibilityPseudonymous:
		return GeneratePseudonym(address)
	case VisibilityRedacted, VisibilityHidden:
		return "[REDACTED]"
	default:
		return "[REDACTED]" // Fail safe
	}
}
