package explorer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// VisibilityMap maps an address (lowercase) to its resolved visibility level
type VisibilityMap map[string]VisibilityLevel

// ContractStore is the minimal interface RedactionEngine needs from the explorer store.
type ContractStore interface {
	GetContract(ctx context.Context, address string) (*Contract, error)
}

// RedactionEngine handles the bulk redaction of explorer data based on user grants
type RedactionEngine struct {
	store ContractStore
	db    Database // The main privacy proxy DB for RBAC checks
}

// Database interface for the methods RedactionEngine needs from the main DB
type Database interface {
	GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (VisibilityMap, error)
	// GetLinkedAddresses returns the lowercase ETH addresses linked to a DID.
	GetLinkedAddresses(ctx context.Context, did string) ([]string, error)
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
		if tx.HasRecipient() {
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

	// 2b. Get the viewer's linked addresses for participant visibility.
	// If the viewer is a participant (from or to) in a transaction, the counterparty
	// address should be visible in that specific transaction — the viewer already
	// knows who they sent to / received from via their own wallet.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	// 3. Apply redactions
	var redactedTxs []Transaction
	for _, tx := range txs {
		// Determine whether the viewer is a participant in this transaction.
		viewerIsFrom := tx.From != "" && viewerAddrs[strings.ToLower(tx.From)]
		viewerIsTo := tx.HasRecipient() && viewerAddrs[strings.ToLower(*tx.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo

		// Resolve base visibility from the shared map.
		baseFromLevel := VisibilityFull
		if tx.From != "" {
			baseFromLevel = visibilityMap[strings.ToLower(tx.From)]
		}
		baseToLevel := VisibilityFull
		if tx.HasRecipient() {
			baseToLevel = visibilityMap[strings.ToLower(*tx.To)]
		}

		// Participant override: the counterparty address is revealed (so we don't
		// replace it with [PRIVATE]), but sensitive metadata like nonce is still
		// stripped based on the BASE visibility — the participant override only
		// makes the address visible, not the sender's activity metadata.
		fromLevel := baseFromLevel
		toLevel := baseToLevel
		if viewerIsParticipant {
			if fromLevel == VisibilityHidden || fromLevel == VisibilityRedacted {
				fromLevel = VisibilityFull
			}
			if toLevel == VisibilityHidden || toLevel == VisibilityRedacted {
				toLevel = VisibilityFull
			}
		}

		// If BOTH participants are non-identifiable to the viewer (hidden or redacted
		// after participant override), drop entirely. Showing "[PRIVATE] → [PRIVATE]"
		// leaks transaction existence and timing without any useful information.
		if isNonIdentifiable(fromLevel) && isNonIdentifiable(toLevel) {
			continue
		}

		// Contract creation transactions: if the deployer is non-identifiable,
		// drop entirely. Showing "[PRIVATE] → Contract" leaks deployment
		// activity, timing, and the resulting contract address.
		if tx.IsContractCreation() && isNonIdentifiable(fromLevel) {
			continue
		}

		redactedTx := tx

		// If one side is non-identifiable (hidden or redacted) but the other is
		// identifiable, replace the non-identifiable side with [PRIVATE] and strip
		// financial data (value, input, error).
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redactedTx.From = "[PRIVATE]"
				// Zero out nonce: it reveals the transaction count of a private account,
				// and sequential nonces across [PRIVATE] transactions could link them to the same account.
				redactedTx.Nonce = nil
			} else {
				redactedTx.From = r.applyRedaction(tx.From, fromLevel)
			}
			if isNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redactedTx.To = &p
			} else if tx.HasRecipient() {
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

		// Neither side is hidden or redacted — apply normal redaction
		if tx.From != "" {
			redactedTx.From = r.applyRedaction(tx.From, fromLevel)
		}
		if tx.HasRecipient() {
			redacted := r.applyRedaction(*tx.To, toLevel)
			redactedTx.To = &redacted
		}

		// Participant override: even when the counterparty address is revealed,
		// strip the sender's nonce if the sender is base-level private. The nonce
		// reveals their lifetime tx count — the receiver doesn't need that.
		if viewerIsParticipant && (baseFromLevel == VisibilityHidden || baseFromLevel == VisibilityRedacted) {
			redactedTx.Nonce = nil
		}

		redactedTxs = append(redactedTxs, redactedTx)
	}

	return redactedTxs, nil
}

// RedactTransfers applies privacy rules to a list of token transfers.
// Like RedactTransactions, participants (viewer is sender or receiver) get a
// visibility override so they can see the transfer amount and counterparty.
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

	// Get viewer's linked addresses for participant visibility override.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	var result []TokenTransfer
	for _, t := range transfers {
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != "" && viewerAddrs[strings.ToLower(t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo

		fromLevel := visMap[strings.ToLower(t.From)]
		toLevel := visMap[strings.ToLower(t.To)]

		// Participant override: reveal counterparty address so the transfer
		// isn't stripped — the viewer already knows who they transacted with.
		if viewerIsParticipant {
			if isNonIdentifiable(fromLevel) {
				fromLevel = VisibilityFull
			}
			if isNonIdentifiable(toLevel) {
				toLevel = VisibilityFull
			}
		}

		// Drop if both sides are non-identifiable
		if isNonIdentifiable(fromLevel) && isNonIdentifiable(toLevel) {
			continue
		}

		redacted := t

		// If one side is non-identifiable, replace with [PRIVATE] and strip amount
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
			}
			if isNonIdentifiable(toLevel) {
				redacted.To = "[PRIVATE]"
			} else {
				redacted.To = r.applyRedaction(t.To, toLevel)
			}
			redacted.Value = JSONString("")
			result = append(result, redacted)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		redacted.To = r.applyRedaction(t.To, toLevel)

		result = append(result, redacted)
	}
	return result, nil
}

// RedactInternalTransactions applies privacy rules to a list of internal transactions.
// Like RedactTransactions, participants get a visibility override.
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

	// Get viewer's linked addresses for participant visibility override.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	var result []InternalTransaction
	for _, t := range itxs {
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != nil && *t.To != "" && viewerAddrs[strings.ToLower(*t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo

		fromLevel := visMap[strings.ToLower(t.From)]
		toLevel := VisibilityFull
		if t.To != nil && *t.To != "" {
			toLevel = visMap[strings.ToLower(*t.To)]
		}

		// Participant override: reveal counterparty.
		if viewerIsParticipant {
			if isNonIdentifiable(fromLevel) {
				fromLevel = VisibilityFull
			}
			if isNonIdentifiable(toLevel) {
				toLevel = VisibilityFull
			}
		}

		// Drop if both sides are non-identifiable
		if isNonIdentifiable(fromLevel) && isNonIdentifiable(toLevel) {
			continue
		}

		redacted := t

		// If one side is non-identifiable, replace with [PRIVATE] and strip financial data
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
			}
			if isNonIdentifiable(toLevel) {
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

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		if t.To != nil && *t.To != "" {
			r2 := r.applyRedaction(*t.To, toLevel)
			redacted.To = &r2
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

// extractDataAddresses parses the ABI-encoded Data field of a log and returns the lowercase
// "0x"-prefixed addresses found in any non-indexed address-typed parameter slots.
// Returns nil if the ABI cannot be parsed, the event is not found, or no address params exist.
func extractDataAddresses(data string, contractABI json.RawMessage, topic0 *string) []string {
	if data == "" || len(contractABI) == 0 || topic0 == nil {
		return nil
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return nil
	}
	// Find the event matching topic0 (keccak256 of its signature).
	topic0Lower := strings.ToLower(*topic0)
	var matchedEvent *abi.Event
	for _, ev := range parsedABI.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev // capture
			matchedEvent = &ev
			break
		}
	}
	if matchedEvent == nil {
		return nil
	}
	// Collect non-indexed inputs in declaration order.
	var nonIndexed []abi.Argument
	for _, inp := range matchedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
		}
	}
	if len(nonIndexed) == 0 {
		return nil
	}

	// Decode the hex data.
	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil
	}
	// Each non-indexed param occupies a 32-byte slot (for value types).
	if len(dataBytes) < len(nonIndexed)*32 {
		return nil
	}

	var addrs []string
	for i, inp := range nonIndexed {
		if inp.Type.T != abi.AddressTy {
			continue
		}
		slot := dataBytes[i*32 : (i+1)*32]
		// Addresses are right-aligned in a 32-byte slot (12 zero bytes of padding on the left).
		prefix := slot[:12]
		allZero := true
		for _, b := range prefix {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}
		addr := common.BytesToAddress(slot[12:]).Hex()
		addrs = append(addrs, strings.ToLower(addr))
	}
	return addrs
}

// redactLogData scans the ABI-encoded Data field of a log for non-indexed address parameters
// and zeros any slot whose address is private (non-Full visibility).
// Returns the original data unchanged if no ABI is registered, the event is not found,
// no address fields exist, or the data cannot be decoded.
func (r *RedactionEngine) redactLogData(data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) string {
	if data == "" || len(contractABI) == 0 || topic0 == nil {
		return data
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return data
	}
	topic0Lower := strings.ToLower(*topic0)
	var matchedEvent *abi.Event
	for _, ev := range parsedABI.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev
			matchedEvent = &ev
			break
		}
	}
	if matchedEvent == nil {
		return data
	}
	var nonIndexed []abi.Argument
	for _, inp := range matchedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
		}
	}
	if len(nonIndexed) == 0 {
		return data
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return data
	}
	if len(dataBytes) < len(nonIndexed)*32 {
		return data
	}

	modified := false
	for i, inp := range nonIndexed {
		if inp.Type.T != abi.AddressTy {
			continue
		}
		slot := dataBytes[i*32 : (i+1)*32]
		prefix := slot[:12]
		allZero := true
		for _, b := range prefix {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}
		addr := strings.ToLower(common.BytesToAddress(slot[12:]).Hex())
		level := visMap[addr]
		if level == VisibilityFull {
			continue
		}
		// Zero out the entire 32-byte slot.
		for j := i*32; j < (i+1)*32; j++ {
			dataBytes[j] = 0
		}
		modified = true
	}
	if !modified {
		return data
	}
	prefix := ""
	if strings.HasPrefix(data, "0x") || strings.HasPrefix(data, "0X") {
		prefix = "0x"
	}
	return prefix + hex.EncodeToString(dataBytes)
}

// RedactLogs applies privacy rules to event logs.
// The log Address field is the contract that emitted the event.
// Hidden contracts are dropped; pseudonymous/redacted contracts have their address masked
// and topic/data stripped to prevent correlation.
// For logs from visible contracts, each topic is additionally scanned for embedded EOA/contract
// addresses (zero-padded 32-byte form). Any embedded address that is private is zeroed out.
// When the emitting contract has a registered ABI, the non-indexed Data field is also scanned
// for address-typed parameters and any private addresses are zeroed.
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

	// Phase 3: ABI-based data scanning for logs from visible/pseudonymous contracts.
	// Fetch ABIs for each unique emitter, extract address-typed non-indexed params from
	// the Data field, and resolve their visibility so they can be zeroed if private.
	contractABIs := make(map[string]json.RawMessage) // address → ABI (nil if not found)
	if r.store != nil {
		abiDataAddrMap := make(map[string]bool)
		for _, l := range logs {
			level := visMap[strings.ToLower(l.Address)]
			if level == VisibilityHidden || level == VisibilityRedacted || l.Data == "" || l.Topic0 == nil {
				continue
			}
			addrKey := strings.ToLower(l.Address)
			if _, cached := contractABIs[addrKey]; !cached {
				contract, err2 := r.store.GetContract(ctx, addrKey)
				if err2 != nil || contract == nil {
					contractABIs[addrKey] = nil
				} else {
					contractABIs[addrKey] = contract.ABI
				}
			}
			if len(contractABIs[addrKey]) == 0 {
				continue
			}
			for _, a := range extractDataAddresses(l.Data, contractABIs[addrKey], l.Topic0) {
				if _, alreadyKnown := visMap[a]; !alreadyKnown {
					abiDataAddrMap[a] = true
				}
			}
		}
		if len(abiDataAddrMap) > 0 {
			abiDataAddrs := make([]string, 0, len(abiDataAddrMap))
			for a := range abiDataAddrMap {
				abiDataAddrs = append(abiDataAddrs, a)
			}
			abiVisMap, err2 := r.db.GetBatchVisibility(ctx, viewerDID, abiDataAddrs)
			if err2 != nil {
				return nil, err2
			}
			for k, v := range abiVisMap {
				visMap[k] = v
			}
		}
	}

	// Phase 4: apply redactions.
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
			// Scan non-indexed Data field for private addresses when ABI is registered.
			if l.Data != "" && l.Topic0 != nil {
				addrKey := strings.ToLower(l.Address)
				if contractABI, ok := contractABIs[addrKey]; ok && len(contractABI) > 0 {
					redacted.Data = r.redactLogData(l.Data, contractABI, l.Topic0, visMap)
				}
			}
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

// isNonIdentifiable returns true if the visibility level means the viewer
// cannot identify the address — it will render as "[PRIVATE]" either way.
func isNonIdentifiable(level VisibilityLevel) bool {
	return level == VisibilityHidden || level == VisibilityRedacted
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
