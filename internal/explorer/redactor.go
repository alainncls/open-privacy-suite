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
		fromLevel := VisibilityFull
		if tx.From != "" {
			fromLevel = visibilityMap[strings.ToLower(tx.From)]
		}

		toLevel := VisibilityFull
		if tx.To != nil && *tx.To != "" {
			toLevel = visibilityMap[strings.ToLower(*tx.To)]
		}

		// If BOTH participants are hidden, drop the transaction entirely
		if fromLevel == VisibilityHidden && toLevel == VisibilityHidden {
			continue
		}

		redactedTx := tx

		// If one side is hidden but the other is visible, replace the hidden
		// side with [PRIVATE] and strip financial data (value, input, error).
		if fromLevel == VisibilityHidden || toLevel == VisibilityHidden {
			if fromLevel == VisibilityHidden {
				redactedTx.From = "[PRIVATE]"
				// Zero out nonce: it reveals the transaction count of a private account,
				// and sequential nonces across [PRIVATE] transactions could link them to the same account.
				redactedTx.Nonce = nil
			} else {
				redactedTx.From = r.applyRedaction(tx.From, fromLevel)
			}
			if toLevel == VisibilityHidden {
				p := "[PRIVATE]"
				redactedTx.To = &p
			} else if tx.To != nil && *tx.To != "" {
				redacted := r.applyRedaction(*tx.To, toLevel)
				redactedTx.To = &redacted
			}
			redactedTx.Value = JSONString("")
			redactedTx.InputData = ""
			redactedTx.Error = nil
			redactedTx.RevertReason = nil
			redactedTxs = append(redactedTxs, redactedTx)
			continue
		}

		// Neither side is hidden — apply normal redaction
		if tx.From != "" {
			redactedTx.From = r.applyRedaction(tx.From, fromLevel)
		}
		if tx.To != nil && *tx.To != "" {
			redacted := r.applyRedaction(*tx.To, toLevel)
			redactedTx.To = &redacted
		}

		// If either participant is redacted, strip the transaction data
		if fromLevel == VisibilityRedacted || toLevel == VisibilityRedacted {
			redactedTx.Value = JSONString("")
			redactedTx.InputData = ""
			redactedTx.Error = nil
			redactedTx.RevertReason = nil
			if fromLevel == VisibilityRedacted {
				redactedTx.Nonce = nil // nonce reveals tx count for private sender
			}
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

		// Drop only if both sides are hidden
		if fromLevel == VisibilityHidden && toLevel == VisibilityHidden {
			continue
		}

		redacted := t

		// If one side is hidden, replace with [PRIVATE] and strip amount
		if fromLevel == VisibilityHidden || toLevel == VisibilityHidden {
			if fromLevel == VisibilityHidden {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
			}
			if toLevel == VisibilityHidden {
				redacted.To = "[PRIVATE]"
			} else {
				redacted.To = r.applyRedaction(t.To, toLevel)
			}
			redacted.Value = JSONString("")
			result = append(result, redacted)
			continue
		}

		// Neither side hidden — apply normal redaction
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

		// Drop only if both sides are hidden
		if fromLevel == VisibilityHidden && toLevel == VisibilityHidden {
			continue
		}

		redacted := t

		// If one side is hidden, replace with [PRIVATE] and strip financial data
		if fromLevel == VisibilityHidden || toLevel == VisibilityHidden {
			if fromLevel == VisibilityHidden {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
			}
			if toLevel == VisibilityHidden {
				p := "[PRIVATE]"
				redacted.To = &p
			} else if t.To != nil && *t.To != "" {
				r2 := r.applyRedaction(*t.To, toLevel)
				redacted.To = &r2
			}
			redacted.Value = JSONString("")
			redacted.Input = nil
			redacted.Output = nil
			result = append(result, redacted)
			continue
		}

		// Neither side hidden — apply normal redaction
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

// extractTopicAddress checks if a 32-byte topic hex string encodes an address
// using the standard zero-padding convention (12 zero bytes = 24 zero hex chars prefix after "0x").
// Returns the lowercase "0x"-prefixed address and true if the pattern matches, otherwise "", false.
func extractTopicAddress(topic string) (string, bool) {
	t := strings.ToLower(topic)
	// Topics are 66 chars: "0x" + 64 hex. Address occupies the last 40 chars.
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return "", false
	}
	prefix := t[2:26] // 24 hex chars = 12 zero bytes of padding
	if strings.Trim(prefix, "0") != "" {
		return "", false
	}
	return "0x" + t[26:], true
}

// redactTopicAddress converts a visibility-redacted embedded address back into a
// zero-padded 32-byte topic value.
func redactTopicAddress(addr string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		a := strings.ToLower(strings.TrimPrefix(addr, "0x"))
		return "0x" + strings.Repeat("0", 24) + a
	case VisibilityPseudonymous:
		// GeneratePseudonym returns a human-readable string, not a hex address.
		// We cannot zero-pad it into a valid 32-byte hex topic, so zero the slot instead.
		return "0x" + strings.Repeat("0", 64)
	default: // VisibilityRedacted, VisibilityHidden
		return "0x" + strings.Repeat("0", 64)
	}
}

// redactTopicField redacts a single topic field if it embeds a private address.
// If the topic does not embed a recognised address pattern it is returned unchanged.
func redactTopicField(topic *string, visMap VisibilityMap) *string {
	if topic == nil {
		return nil
	}
	addr, ok := extractTopicAddress(*topic)
	if !ok {
		return topic
	}
	level := visMap[addr]
	if level == VisibilityFull {
		return topic
	}
	redacted := redactTopicAddress(addr, level)
	return &redacted
}

// RedactLogs applies privacy rules to event logs.
// The log Address field is the contract that emitted the event.
// Hidden contracts are dropped; pseudonymous/redacted contracts have their address masked
// and topic/data stripped to prevent correlation.
// For logs from visible contracts, each topic is additionally scanned for embedded EOA/contract
// addresses (zero-padded 32-byte form). Any embedded address that is private is zeroed out.
//
// TODO: The Data field may also contain ABI-encoded private addresses. Full redaction would
// require ABI decoding and per-field visibility checks — skipped for now due to complexity.
func (r *RedactionEngine) RedactLogs(ctx context.Context, logs []Log, viewerDID string) ([]Log, error) {
	if len(logs) == 0 {
		return logs, nil
	}

	// Phase 1: collect emitting contract addresses and do an initial batch lookup.
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

	// Phase 2: for logs that will be kept with full/pseudonymous disclosure,
	// scan topics for embedded addresses not yet in visMap.
	extraAddrMap := make(map[string]bool)
	for _, l := range logs {
		level := visMap[strings.ToLower(l.Address)]
		// Redacted contracts already have all topics stripped; hidden contracts are dropped.
		if level == VisibilityHidden || level == VisibilityRedacted {
			continue
		}
		for _, t := range []*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3} {
			if t == nil {
				continue
			}
			addr, ok := extractTopicAddress(*t)
			if !ok {
				continue
			}
			if _, alreadyKnown := visMap[addr]; !alreadyKnown {
				extraAddrMap[addr] = true
			}
		}
	}

	if len(extraAddrMap) > 0 {
		extraAddrs := make([]string, 0, len(extraAddrMap))
		for a := range extraAddrMap {
			extraAddrs = append(extraAddrs, a)
		}
		extraVisMap, err := r.db.GetBatchVisibility(ctx, viewerDID, extraAddrs)
		if err != nil {
			return nil, err
		}
		for k, v := range extraVisMap {
			visMap[k] = v
		}
	}

	// Phase 3: apply redactions.
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
		} else {
			// Contract is visible — scan topics for embedded private addresses.
			redacted.Topic0 = redactTopicField(l.Topic0, visMap)
			redacted.Topic1 = redactTopicField(l.Topic1, visMap)
			redacted.Topic2 = redactTopicField(l.Topic2, visMap)
			redacted.Topic3 = redactTopicField(l.Topic3, visMap)
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
		if level == VisibilityRedacted {
			// Strip balance and percentage: they reveal financial position even when the address is masked.
			h.Balance = JSONString("")
			h.Percentage = 0
		}
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
