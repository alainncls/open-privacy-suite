package rbac

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ABIProvider looks up the ABI for a contract address. Returns empty string if
// the ABI is not available. Addresses are lowercase with 0x prefix.
type ABIProvider interface {
	GetContractABI(address string) string
}

// logEntry is the minimal structure needed to inspect an Ethereum log for
// event filtering. Fields mirror the JSON-RPC log representation.
type logEntry struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// FilterEventLogs filters a slice of raw JSON log entries based on the caller's
// event rules from their effective permissions.
//
// Semantics:
//   - If no grants have event_rules for a log's contract: pass the log through (backward compat).
//   - If any grant has event_rules: allowlist mode — only listed topic0s pass.
//   - For rules with ParamRules ("self" constraints): the log must also have
//     the caller's address in the constrained parameter positions (OR semantics
//     across multiple ParamRules on the same event).
//   - Union semantics across grants: if any grant allows the event, it passes.
//
// userAddresses are the caller's linked ETH addresses (lowercase 0x-prefixed).
// perms contains the resolved effective permissions with ContractAccess and EventRules.
// abiProvider supplies contract ABIs for param rule decoding (may be nil).
func FilterEventLogs(
	logs []json.RawMessage,
	perms *EffectivePermissions,
	userAddresses []string,
	abiProvider ABIProvider,
) []json.RawMessage {
	if len(logs) == 0 || perms == nil {
		return logs
	}

	// Build lowercase address set for O(1) lookup.
	addrSet := make(map[string]bool, len(userAddresses))
	for _, a := range userAddresses {
		addrSet[strings.ToLower(a)] = true
	}

	filtered := make([]json.RawMessage, 0, len(logs))
	for _, rawLog := range logs {
		var entry logEntry
		if err := json.Unmarshal(rawLog, &entry); err != nil {
			continue // skip malformed
		}

		contractAddr := strings.ToLower(entry.Address)
		access := perms.GetContractAccess(contractAddr)
		if access == nil {
			// No access to this contract at all — hide the log.
			continue
		}

		// If no event rules configured on this contract access, apply default
		// address-based filtering: log visible only if user's address appears
		// in any topic (backward compat with pre-event-rules behavior).
		if access.EventRules == nil {
			if logHasUserAddress(entry, addrSet) {
				filtered = append(filtered, rawLog)
			}
			continue
		}

		// Allowlist mode: the log's topic0 must match one of the allowed event rules.
		if len(entry.Topics) == 0 {
			// Anonymous event (no topic0) — blocked in allowlist mode.
			continue
		}

		topic0 := strings.ToLower(entry.Topics[0])
		if eventAllowed(topic0, entry, access.EventRules, addrSet, contractAddr, abiProvider) {
			filtered = append(filtered, rawLog)
		}
	}

	return filtered
}

// logHasUserAddress checks if any topic in the log entry encodes one of the
// user's linked addresses. This is the default filtering when no event rules
// are configured (backward compat).
func logHasUserAddress(entry logEntry, addrSet map[string]bool) bool {
	for _, topic := range entry.Topics {
		if topicMatchesAddr(topic, addrSet) {
			return true
		}
	}
	return false
}

// eventAllowed checks if a log with the given topic0 is allowed by any of the
// event rules. Returns true if the event is in the allowlist and all param
// constraints are satisfied.
func eventAllowed(
	topic0 string,
	entry logEntry,
	rules []EventRule,
	addrSet map[string]bool,
	contractAddr string,
	abiProvider ABIProvider,
) bool {
	for _, rule := range rules {
		if !strings.EqualFold(rule.Topic0, topic0) {
			continue
		}

		// Topic0 matches this rule. If no param rules, event is allowed.
		if len(rule.ParamRules) == 0 {
			return true
		}

		// Check param rules: at least one "self" constraint must match (OR semantics).
		if checkEventParamRules(entry, rule.ParamRules, addrSet, contractAddr, abiProvider) {
			return true
		}
	}
	return false
}

// checkEventParamRules checks if the caller satisfies any of the param rule
// constraints on an event. OR semantics: if the user's address appears in
// ANY constrained parameter position, the check passes.
func checkEventParamRules(
	entry logEntry,
	paramRules []ParamRule,
	addrSet map[string]bool,
	contractAddr string,
	abiProvider ABIProvider,
) bool {
	// We need to resolve each param by index. For indexed params, they appear
	// in topics[1..3]. For non-indexed params, they're ABI-encoded in data.
	// To know which params are indexed we need the ABI.
	var parsedEvent *abi.Event
	if abiProvider != nil {
		contractABI := abiProvider.GetContractABI(contractAddr)
		if contractABI != "" {
			parsedEvent = findEventByTopic0(contractABI, entry.Topics[0])
		}
	}

	for _, pr := range paramRules {
		if pr.MustBe != "self" {
			continue
		}

		if matchesParamSelf(entry, pr.Index, addrSet, parsedEvent) {
			return true // OR semantics — one match is enough
		}
	}

	return false
}

// matchesParamSelf checks if the event parameter at the given ABI index
// encodes one of the user's linked addresses.
func matchesParamSelf(
	entry logEntry,
	paramIndex int,
	addrSet map[string]bool,
	parsedEvent *abi.Event,
) bool {
	if parsedEvent == nil {
		// No ABI: fall back to checking topics for address-like values.
		// Indexed param at ABI index i goes to topics[1+indexedOffset].
		// Without ABI we can only check if the index maps to a topic position.
		topicIdx := paramIndex + 1 // rough guess: assume all params up to index are indexed
		if topicIdx < len(entry.Topics) {
			return topicMatchesAddr(entry.Topics[topicIdx], addrSet)
		}
		return false
	}

	if paramIndex < 0 || paramIndex >= len(parsedEvent.Inputs) {
		return false
	}

	input := parsedEvent.Inputs[paramIndex]
	if input.Indexed {
		// Find which topic slot this indexed param occupies.
		// topics[0] = event signature. topics[1..3] = indexed params in order.
		indexedPos := 0
		for i := 0; i < paramIndex; i++ {
			if parsedEvent.Inputs[i].Indexed {
				indexedPos++
			}
		}
		topicSlot := indexedPos + 1
		if topicSlot < len(entry.Topics) {
			return topicMatchesAddr(entry.Topics[topicSlot], addrSet)
		}
		return false
	}

	// Non-indexed param: ABI-decode the data field.
	return dataParamMatchesAddr(entry.Data, parsedEvent, paramIndex, addrSet)
}

// topicMatchesAddr checks if a 32-byte topic hex string encodes one of the
// user's addresses (zero-padded address format).
func topicMatchesAddr(topic string, addrSet map[string]bool) bool {
	t := strings.ToLower(topic)
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return false
	}
	// Address is last 40 chars, first 24 chars must be zero padding.
	prefix := t[2:26]
	if strings.Trim(prefix, "0") != "" {
		return false
	}
	addr := "0x" + t[26:]
	return addrSet[addr]
}

// dataParamMatchesAddr decodes the non-indexed parameters from the log data
// field and checks if the parameter at paramIndex is an address matching one
// of the user's addresses.
func dataParamMatchesAddr(
	data string,
	parsedEvent *abi.Event,
	paramIndex int,
	addrSet map[string]bool,
) bool {
	if data == "" || data == "0x" {
		return false
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return false
	}

	// Collect non-indexed inputs to determine ABI decode ordering.
	var nonIndexed abi.Arguments
	nonIndexedABIIdx := -1
	niCount := 0
	for i, inp := range parsedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
			if i == paramIndex {
				nonIndexedABIIdx = niCount
			}
			niCount++
		}
	}

	if nonIndexedABIIdx < 0 {
		return false // param is not non-indexed (shouldn't happen, handled above)
	}

	// Attempt ABI unpack.
	values, err := nonIndexed.Unpack(dataBytes)
	if err != nil {
		return false
	}

	if nonIndexedABIIdx >= len(values) {
		return false
	}

	addr, ok := values[nonIndexedABIIdx].(common.Address)
	if !ok {
		return false
	}

	return addrSet[strings.ToLower(addr.Hex())]
}

// findEventByTopic0 finds the event in a contract ABI that matches the given topic0.
func findEventByTopic0(contractABI string, topic0 string) *abi.Event {
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil
	}
	topic0Lower := strings.ToLower(topic0)
	for _, ev := range parsed.Events {
		sig := "0x" + hex.EncodeToString(ev.ID.Bytes())
		if strings.ToLower(sig) == topic0Lower {
			ev := ev // capture
			return &ev
		}
	}
	return nil
}
