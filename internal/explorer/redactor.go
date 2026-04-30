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

// EventRuleChecker resolves event-level access rules for a viewer on a
// given contract address. The interface mirrors the RPC-side event-rule
// resolution (see rbac.FilterEventLogs) so the explorer redactor and the
// JSON-RPC filter behave identically — required by the Layer 1 / Layer 2
// symmetry invariant in REDACTION_SPEC.md.
//
// Returns a tri-state EventRulesResolution:
//   - Wildcard == true                  ⇒ all events for this contract are
//                                          visible to the viewer; allowlist
//                                          is irrelevant. Mirrors the
//                                          rbac.EventRulesField{"*"} state.
//   - Wildcard == false, len(Rules) > 0 ⇒ allowlist mode; only listed
//                                          topic0s pass.
//   - Wildcard == false, len(Rules) == 0 ⇒ **deny-all** (RD-842 / RD-888).
//                                          Same as `event_rules: null` in
//                                          the database — operator intent
//                                          is "no events visible until
//                                          rules are configured." Anonymous
//                                          logs (no topic0) are also
//                                          blocked in this mode.
//
// Implementations MUST return the deny-all state when there is no
// applicable grant for the viewer on the contract. **Never default to
// allow-on-missing** — that was the pre-RD-888 behaviour and the cause of
// the RPC/explorer symmetry break (RPC denied, explorer leaked).
type EventRuleChecker interface {
	// GetEventRulesForContract returns the viewer's event-rule resolution
	// for a contract address. See the interface docstring for tri-state
	// semantics.
	GetEventRulesForContract(ctx context.Context, viewerDID string, contractAddress string) EventRulesResolution
}

// EventRulesResolution describes a viewer's event-rule access for one
// contract. See EventRuleChecker docstring for tri-state semantics.
type EventRulesResolution struct {
	// Wildcard true ⇒ all events visible, allowlist ignored.
	Wildcard bool
	// Rules is the allowlist of (topic0) entries. Honoured only when
	// Wildcard is false. Empty Rules with Wildcard=false ⇒ deny-all.
	Rules []EventRuleInfo
}

// EventRuleInfo is a lightweight event rule representation used by the redactor.
type EventRuleInfo struct {
	Topic0 string // event signature hash (0x-prefixed, lowercase)
}

// RedactionEngine handles the bulk redaction of explorer data based on user grants
type RedactionEngine struct {
	store            ContractStore
	db               Database // The main privacy proxy DB for RBAC checks
	eventRuleChecker EventRuleChecker
}

// Database interface for the methods RedactionEngine needs from the main DB
type Database interface {
	GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (VisibilityMap, error)
	GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]AddressVisibility, error)
	// GetLinkedAddresses returns the lowercase ETH addresses linked to a DID.
	GetLinkedAddresses(ctx context.Context, did string) ([]string, error)
	// GetBatchEventAccess checks which contracts the viewer has event/log access to.
	// Returns a map of lowercase contract address -> bool (true = has event access).
	// A viewer has event access if they are an org admin or have a contract_grant
	// with non-empty event_rules (event_rules IS NOT NULL AND event_rules != '[]').
	GetBatchEventAccess(ctx context.Context, viewerDID string, contractAddresses []string) (map[string]bool, error)
}

func NewRedactionEngine(store ContractStore, db Database) *RedactionEngine {
	return &RedactionEngine{
		store: store,
		db:    db,
	}
}

// SetEventRuleChecker sets an optional event rule checker for log-level filtering.
func (r *RedactionEngine) SetEventRuleChecker(checker EventRuleChecker) {
	r.eventRuleChecker = checker
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

// isViewerInCalldata checks if any of the viewer's addresses appear as an
// address parameter in the transaction's input data. This detects participation
// in contract calls where the actual counterparty is encoded in calldata rather
// than in the tx-level "to" field (e.g., ERC20 transfer(address,uint256)).
//
// Supported function selectors:
//   - 0xa9059cbb: transfer(address to, uint256 amount)      — to at bytes 4-36
//   - 0x23b872dd: transferFrom(address from, address to, uint256 amount) — from at 4-36, to at 36-68
//   - 0x095ea7b3: approve(address spender, uint256 amount)  — spender at bytes 4-36
func isViewerInCalldata(inputData string, viewerAddrs map[string]bool) bool {
	if len(viewerAddrs) == 0 || len(inputData) < 8 {
		return false
	}

	data := strings.ToLower(inputData)
	// Normalize: strip 0x prefix if present so selector is always at [0:8]
	if strings.HasPrefix(data, "0x") {
		data = data[2:]
	}
	if len(data) < 8 {
		return false
	}
	selector := "0x" + data[:8]

	// Each address param is 32 bytes (64 hex chars), zero-padded on the left.
	// Address is in the last 20 bytes: offset 24 hex chars from param start.
	extractAddr := func(offset int) string {
		start := 8 + offset*64 // 8 = selector length after stripping 0x
		end := start + 64
		if len(data) < end {
			return ""
		}
		// Address is last 20 bytes of 32-byte word
		return "0x" + data[start+24:end]
	}

	switch selector {
	case "0xa9059cbb": // transfer(address,uint256) — param 0 is recipient
		return viewerAddrs[extractAddr(0)]
	case "0x23b872dd": // transferFrom(address,address,uint256) — param 0 is from, param 1 is to
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	case "0x095ea7b3": // approve(address,uint256) — param 0 is spender
		return viewerAddrs[extractAddr(0)]
	}
	return false
}

// RedactOpts provides optional overrides for transaction redaction.
type RedactOpts struct {
	// VisibleTxHashes is the set of tx hashes that are always visible to
	// the viewer (via the visibleTo param). Transactions matching these
	// hashes are never dropped, and their addresses get full visibility.
	VisibleTxHashes map[string]bool

	// ViewerIsAdmin indicates the viewer has admin-level access (org admin
	// or admin claim). Admins see all contract activity including txs from
	// private users — G10 non-participant drop does not apply to admins.
	ViewerIsAdmin bool
}

// RedactTransactions applies privacy rules to a list of transactions.
// Optional RedactOpts can override drop behavior for visibleTo transactions.
func (r *RedactionEngine) RedactTransactions(ctx context.Context, txs []Transaction, viewerDID string, opts ...RedactOpts) ([]Transaction, error) {
	if len(txs) == 0 {
		return txs, nil
	}

	var visibleHashes map[string]bool
	var viewerIsAdmin bool
	if len(opts) > 0 {
		visibleHashes = opts[0].VisibleTxHashes
		viewerIsAdmin = opts[0].ViewerIsAdmin
	}

	// 1. Extract unique addresses
	uniqueAddrs := extractUniqueAddresses(txs)

	// 2. Get batch visibility (authoritative levels) + detailed (for reason metadata)
	visibilityMap, err := r.db.GetBatchVisibility(ctx, viewerDID, uniqueAddrs)
	if err != nil {
		return nil, err
	}
	visibilityMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, uniqueAddrs)
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
		// Check tx-level from/to AND calldata-level recipients (e.g. ERC20
		// transfer(address,uint256) encodes the real recipient in calldata,
		// while tx.To is just the contract address).
		viewerIsFrom := tx.From != "" && viewerAddrs[strings.ToLower(tx.From)]
		viewerIsTo := tx.HasRecipient() && viewerAddrs[strings.ToLower(*tx.To)]
		viewerIsCalldataRecipient := isViewerInCalldata(tx.InputData, viewerAddrs)
		viewerIsParticipant := viewerIsFrom || viewerIsTo || viewerIsCalldataRecipient

		// Resolve base visibility from the shared map.
		baseFromLevel := VisibilityFull
		if tx.From != "" {
			baseFromLevel = visibilityMap[strings.ToLower(tx.From)]
		}
		baseToLevel := VisibilityFull
		if tx.HasRecipient() {
			baseToLevel = visibilityMap[strings.ToLower(*tx.To)]
		}

		// visibleTo override: if this tx was shared with the viewer via the
		// visibleTo param, upgrade both addresses to full visibility — the
		// sender explicitly chose to share this transaction with the viewer.
		txVisibleToViewer := visibleHashes[strings.ToLower(tx.Hash)]

		// Participant override: the counterparty address is revealed (so we don't
		// replace it with [PRIVATE]), but sensitive metadata like nonce is still
		// stripped based on the BASE visibility — the participant override only
		// makes the address visible, not the sender's activity metadata.
		fromLevel := baseFromLevel
		toLevel := baseToLevel
		if viewerIsParticipant || txVisibleToViewer {
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

		// G10 fix: Non-participant, non-visibleTo txs where one side is hidden
		// are dropped. This aligns explorer visibility with the RPC layer.
		// Exceptions:
		// - Admins see all contract activity (they need to audit the network)
		// - Both sides Full = both identifiable, no information leak
		if !viewerIsParticipant && !txVisibleToViewer && !viewerIsAdmin {
			if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
				continue
			}
		}

		redactedTx := tx
		redactedTx.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && isNonIdentifiable(baseLvl) {
				redactedTx.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && isNonIdentifiable(baseLvl) {
				redactedTx.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visibilityMapDetailed[aLower]; ok {
				redactedTx.AddressMetadata[aLower] = meta.Reason
			}
		}

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
				setMeta(tx.From, baseFromLevel)
			}
			if isNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redactedTx.To = &p
			} else if tx.HasRecipient() {
				redacted := r.applyRedaction(*tx.To, toLevel)
				redactedTx.To = &redacted
				setMeta(*tx.To, baseToLevel)
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
			setMeta(tx.From, baseFromLevel)
		}
		if tx.HasRecipient() {
			redacted := r.applyRedaction(*tx.To, toLevel)
			redactedTx.To = &redacted
			setMeta(*tx.To, baseToLevel)
		}

		// Participant override: even when the counterparty address is revealed,
		// strip the sender's nonce if the sender is base-level private. The nonce
		// reveals their lifetime tx count — the receiver doesn't need that.
		if viewerIsParticipant && (baseFromLevel == VisibilityHidden || baseFromLevel == VisibilityRedacted) {
			redactedTx.Nonce = nil
		}

		redactedTxs = append(redactedTxs, redactedTx)
	}

	// Strip token transfer info from transactions where the viewer lacks event access
	// to the target contract. Token transfers are derived from Transfer event logs,
	// so they should only be visible when the viewer has event/log access.
	if !viewerIsAdmin {
		tokenContractAddrs := make(map[string]bool)
		for i := range redactedTxs {
			if redactedTxs[i].TokenTransferCount > 0 && redactedTxs[i].HasRecipient() {
				tokenContractAddrs[strings.ToLower(*redactedTxs[i].To)] = true
			}
		}
		if len(tokenContractAddrs) > 0 {
			addrs := make([]string, 0, len(tokenContractAddrs))
			for a := range tokenContractAddrs {
				addrs = append(addrs, a)
			}
			eventAccess, err := r.db.GetBatchEventAccess(ctx, viewerDID, addrs)
			if err != nil {
				return nil, err
			}
			for i := range redactedTxs {
				if redactedTxs[i].TokenTransferCount > 0 && redactedTxs[i].HasRecipient() {
					toAddr := strings.ToLower(*redactedTxs[i].To)
					if !eventAccess[toAddr] {
						redactedTxs[i].TokenTransferCount = 0
						redactedTxs[i].TxCategories = removeCategory(redactedTxs[i].TxCategories, "token_transfer")
						// If stripping "token_transfer" left no categories, restore
						// "contract_call" — the tx still called a contract.
						// Note: can't check InputData here because it may have been
						// stripped by the redaction loop above.
						if len(redactedTxs[i].TxCategories) == 0 && redactedTxs[i].HasRecipient() {
							redactedTxs[i].TxCategories = []string{"contract_call"}
						}
					}
				}
			}
		}
	}

	return redactedTxs, nil
}

func removeCategory(cats []string, remove string) []string {
	var result []string
	for _, c := range cats {
		if c != remove {
			result = append(result, c)
		}
	}
	return result
}

// RedactTransfers applies privacy rules to a list of token transfers.
// Like RedactTransactions, participants (viewer is sender or receiver) get a
// visibility override so they can see the transfer amount and counterparty.
func (r *RedactionEngine) RedactTransfers(ctx context.Context, transfers []TokenTransfer, viewerDID string, opts ...RedactOpts) ([]TokenTransfer, error) {
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
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
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

	var visibleHashes map[string]bool
	var viewerIsAdminT bool
	if len(opts) > 0 {
		visibleHashes = opts[0].VisibleTxHashes
		viewerIsAdminT = opts[0].ViewerIsAdmin
	}

	var result []TokenTransfer
	for _, t := range transfers {
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != "" && viewerAddrs[strings.ToLower(t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo
		txVisibleToViewer := visibleHashes[strings.ToLower(t.TxHash)]

		baseFromLevel := visMap[strings.ToLower(t.From)]
		baseToLevel := visMap[strings.ToLower(t.To)]
		fromLevel := baseFromLevel
		toLevel := baseToLevel

		// Participant or visibleTo override
		if viewerIsParticipant || txVisibleToViewer {
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

		// G10: non-participant, non-visibleTo, non-admin, one side hidden → drop
		if !viewerIsParticipant && !txVisibleToViewer && !viewerIsAdminT {
			if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
				continue
			}
		}

		redacted := t
		redacted.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visMapDetailed[aLower]; ok {
				redacted.AddressMetadata[aLower] = meta.Reason
			}
		}

		// If one side is non-identifiable, replace with [PRIVATE] and strip amount
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
				setMeta(t.From, baseFromLevel)
			}
			if isNonIdentifiable(toLevel) {
				redacted.To = "[PRIVATE]"
			} else {
				redacted.To = r.applyRedaction(t.To, toLevel)
				setMeta(t.To, baseToLevel)
			}
			redacted.Value = JSONString("")
			result = append(result, redacted)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		setMeta(t.From, baseFromLevel)
		redacted.To = r.applyRedaction(t.To, toLevel)
		setMeta(t.To, baseToLevel)

		result = append(result, redacted)
	}

	// Strip transfers where the viewer lacks event access to the token contract.
	if !viewerIsAdminT && len(result) > 0 {
		tokenAddrs := make(map[string]bool)
		for _, t := range result {
			if t.TokenAddress != "" {
				tokenAddrs[strings.ToLower(t.TokenAddress)] = true
			}
		}
		if len(tokenAddrs) > 0 {
			addrs := make([]string, 0, len(tokenAddrs))
			for a := range tokenAddrs {
				addrs = append(addrs, a)
			}
			eventAccess, err := r.db.GetBatchEventAccess(ctx, viewerDID, addrs)
			if err != nil {
				return nil, err
			}
			var filtered []TokenTransfer
			for _, t := range result {
				if eventAccess[strings.ToLower(t.TokenAddress)] {
					filtered = append(filtered, t)
				}
			}
			result = filtered
		}
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
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
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

		baseFromLevel := visMap[strings.ToLower(t.From)]
		baseToLevel := VisibilityFull
		if t.To != nil && *t.To != "" {
			baseToLevel = visMap[strings.ToLower(*t.To)]
		}
		fromLevel := baseFromLevel
		toLevel := baseToLevel

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
		redacted.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if meta, ok := visMapDetailed[aLower]; ok {
				redacted.AddressMetadata[aLower] = meta.Reason
			}
		}

		// If one side is non-identifiable, replace with [PRIVATE] and strip financial data
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
				setMeta(t.From, baseFromLevel)
			}
			if isNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redacted.To = &p
			} else if t.To != nil && *t.To != "" {
				r2 := r.applyRedaction(*t.To, toLevel)
				redacted.To = &r2
				setMeta(*t.To, baseToLevel)
			}
			redacted.Value = JSONString("")
			redacted.Input = nil
			redacted.Output = nil
			result = append(result, redacted)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		setMeta(t.From, baseFromLevel)
		if t.To != nil && *t.To != "" {
			r2 := r.applyRedaction(*t.To, toLevel)
			redacted.To = &r2
			setMeta(*t.To, baseToLevel)
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
// RedactLogs applies privacy rules to transaction logs. If participantAddrs
// contains the viewer's addresses (e.g. from the parent tx's from/to), logs
// from Redacted contracts are kept (with topics/data intact) instead of being
// stripped — the viewer is a direct participant and already knows the contract.
func (r *RedactionEngine) RedactLogs(ctx context.Context, logs []Log, viewerDID string, participantAddrs ...string) ([]Log, error) {
	return r.RedactLogsWithOpts(ctx, logs, viewerDID, nil, participantAddrs...)
}

// RedactLogsWithOpts is RedactLogs with visibleTo support.
func (r *RedactionEngine) RedactLogsWithOpts(ctx context.Context, logs []Log, viewerDID string, opts *RedactOpts, participantAddrs ...string) ([]Log, error) {
	var visibleTxHashes map[string]bool
	if opts != nil {
		visibleTxHashes = opts.VisibleTxHashes
	}
	if len(logs) == 0 {
		return logs, nil
	}

	// Build set of viewer's own linked addresses.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err == nil {
			for _, a := range linked {
				viewerAddrs[strings.ToLower(a)] = true
			}
		}
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
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}
	masterMeta := make(map[string]VisibilityReason)
	for k, v := range visMapDetailed {
		masterMeta[k] = v.Reason
	}

	// Check if viewer is actually a participant in the parent tx.
	isParticipant := false
	for _, pa := range participantAddrs {
		if pa != "" && viewerAddrs[strings.ToLower(pa)] {
			isParticipant = true
			break
		}
	}

	// Phase 2: for logs that will be kept (full/pseudonymous or participant override),
	// scan topics for embedded addresses not yet in visMap.
	extraAddrMap := make(map[string]bool)
	for _, l := range logs {
		level := visMap[strings.ToLower(l.Address)]
		// Redacted/hidden contracts are scanned if viewer is a participant
		// or the tx is in the viewer's visibleTo set.
		logVisibleTo := visibleTxHashes[strings.ToLower(l.TxHash)]
		if (level == VisibilityHidden || level == VisibilityRedacted) && !isParticipant && !logVisibleTo {
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
		extraVisMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, extraAddrs)
		if err != nil {
			return nil, err
		}
		for k, v := range extraVisMapDetailed {
			masterMeta[k] = v.Reason
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
			abiVisMapDetailed, err2 := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, abiDataAddrs)
			if err2 != nil {
				return nil, err2
			}
			for k, v := range abiVisMapDetailed {
				masterMeta[k] = v.Reason
			}
		}
	}

	// Phase 3b: resolve event rules for each unique emitting contract (if checker is set).
	eventRulesMap := make(map[string]EventRulesResolution) // address -> tri-state resolution
	eventRulesResolved := make(map[string]bool)            // true once we've called the checker for an address
	if r.eventRuleChecker != nil && viewerDID != "" {
		for addr := range addrMap {
			eventRulesMap[addr] = r.eventRuleChecker.GetEventRulesForContract(ctx, viewerDID, addr)
			eventRulesResolved[addr] = true
		}
	}

	// Phase 4: apply redactions.
	var result []Log
	for _, l := range logs {
		level := visMap[strings.ToLower(l.Address)]

		// Participant override: if the viewer is from/to of the parent tx,
		// upgrade Redacted emitting contracts so they can see their own logs.
		if level == VisibilityRedacted && isParticipant {
			level = VisibilityFull
		}

		// visibleTo override: if the tx that produced this log was shared
		// with the viewer, upgrade Hidden/Redacted to Full.
		if (level == VisibilityHidden || level == VisibilityRedacted) && visibleTxHashes[strings.ToLower(l.TxHash)] {
			level = VisibilityFull
		}

		if level == VisibilityHidden {
			continue
		}

		// Event rule check (RD-888): mirrors the RPC layer's tri-state
		// semantics in rbac.FilterEventLogs.
		//   * Wildcard ⇒ pass.
		//   * Allowlist ⇒ topic0 must match a listed entry (anonymous
		//     events with no topic0 are always blocked here).
		//   * Empty Rules + !Wildcard ⇒ **deny-all** (operator intent
		//     of `event_rules: null`). Pre-RD-888 this branch leaked logs
		//     because the explorer treated it as "no rules ⇒ allow."
		contractAddr := strings.ToLower(l.Address)
		if eventRulesResolved[contractAddr] {
			res := eventRulesMap[contractAddr]
			if !res.Wildcard {
				if len(res.Rules) == 0 {
					// Deny-all.
					continue
				}
				// Allowlist mode: anonymous events have no topic0, drop.
				if l.Topic0 == nil {
					continue
				}
				topic0Lower := strings.ToLower(*l.Topic0)
				allowed := false
				for _, rule := range res.Rules {
					if rule.Topic0 == topic0Lower {
						allowed = true
						break
					}
				}
				if !allowed {
					continue
				}
			}
		}

		redacted := l
		redacted.AddressMetadata = make(map[string]VisibilityReason)

		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if isParticipant && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if reason, ok := masterMeta[aLower]; ok {
				redacted.AddressMetadata[aLower] = reason
			}
		}

		redacted.Address = r.applyRedaction(l.Address, level)
		setMeta(l.Address, visMap[strings.ToLower(l.Address)])

		if level == VisibilityRedacted {
			redacted.Topic0 = nil
			redacted.Topic1 = nil
			redacted.Topic2 = nil
			redacted.Topic3 = nil
			redacted.Data = ""
		} else {
			// Contract is visible — scan topics for embedded private addresses.
			redacted.Topic0 = redactTopicField(l.Topic0, visMap)
			if l.Topic0 != nil {
				if a, ok := extractTopicAddress(*l.Topic0); ok {
					setMeta(a, visMap[a])
				}
			}
			redacted.Topic1 = redactTopicField(l.Topic1, visMap)
			if l.Topic1 != nil {
				if a, ok := extractTopicAddress(*l.Topic1); ok {
					setMeta(a, visMap[a])
				}
			}
			redacted.Topic2 = redactTopicField(l.Topic2, visMap)
			if l.Topic2 != nil {
				if a, ok := extractTopicAddress(*l.Topic2); ok {
					setMeta(a, visMap[a])
				}
			}
			redacted.Topic3 = redactTopicField(l.Topic3, visMap)
			if l.Topic3 != nil {
				if a, ok := extractTopicAddress(*l.Topic3); ok {
					setMeta(a, visMap[a])
				}
			}
			// Scan non-indexed Data field for private addresses when ABI is registered.
			if l.Data != "" && l.Topic0 != nil {
				addrKey := strings.ToLower(l.Address)
				if contractABI, ok := contractABIs[addrKey]; ok && len(contractABI) > 0 {
					for _, a := range extractDataAddresses(l.Data, contractABI, l.Topic0) {
						setMeta(a, visMap[a])
					}
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
