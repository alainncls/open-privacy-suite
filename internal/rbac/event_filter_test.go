package rbac

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// testABIProvider is a simple ABIProvider for tests.
type testABIProvider struct {
	abis map[string]string
}

func (p *testABIProvider) GetContractABI(address string) string {
	return p.abis[address]
}

func TestFilterEventLogs_NoEventRules_DefaultAddressFilter(t *testing.T) {
	// When no event rules are configured (nil), default address-based filtering
	// applies: log visible only if user's address appears in a topic.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]
	otherTopic := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	eventSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil, // no event rules = default address-based filtering
			},
		},
	}

	logs := []json.RawMessage{
		// User's address in topic — should be visible.
		json.RawMessage(`{"address":"0xcontract1","topics":["` + eventSig + `","` + userTopic + `"],"data":"0x"}`),
		// No user address in any topic — should be hidden.
		json.RawMessage(`{"address":"0xcontract1","topics":["` + eventSig + `","` + otherTopic + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (only where user address in topic), got %d", len(result))
	}
}

func TestFilterEventLogs_AllowlistMode(t *testing.T) {
	// When event rules exist, only listed topic0s pass.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: "0xabc0000000000000000000000000000000000000000000000000000000000000", Name: "AllowedEvent"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["0xdef0000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log, got %d", len(result))
	}
}

func TestFilterEventLogs_AnonymousEventsBlocked(t *testing.T) {
	// Anonymous events (no topics) are blocked in allowlist mode.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: "0xabc0000000000000000000000000000000000000000000000000000000000000", Name: "Transfer"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":[],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (anonymous blocked), got %d", len(result))
	}
}

func TestFilterEventLogs_NoContractAccess(t *testing.T) {
	// Logs from contracts the user has no access to are hidden.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {Claims: []Claim{ClaimRead}},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xunknown","topics":["0xabc"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (no access), got %d", len(result))
	}
}

func TestFilterEventLogs_ParamRules_IndexedParam(t *testing.T) {
	// Transfer(address indexed from, address indexed to, uint256 value)
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"}, // from must be self
							{Index: 1, MustBe: "self"}, // OR to must be self
						},
					},
				},
			},
		},
	}

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// User is the "from" address (indexed, goes to topics[1])
	userTopic := "0x000000000000000000000000" + userAddr[2:]
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	// Log where user is sender
	log1 := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	// Log where user is neither sender nor recipient
	log2 := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{
		json.RawMessage(log1),
		json.RawMessage(log2),
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}
	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)

	if len(result) != 1 {
		t.Errorf("expected 1 log (user is sender), got %d", len(result))
	}
}

func TestFilterEventLogs_NilVsEmptyEventRules(t *testing.T) {
	// nil EventRules means "default address-based filtering" (user's address must be in a topic).
	// Empty slice [] means "allowlist mode with nothing allowed" (all events blocked).
	contractAddr := "0xcontract1"
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]
	otherTopic := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	logWithUser := json.RawMessage(`{"address":"0xcontract1","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000","` + userTopic + `"],"data":"0x"}`)
	logWithoutUser := json.RawMessage(`{"address":"0xcontract1","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000","` + otherTopic + `"],"data":"0x"}`)

	// nil EventRules: address-based filtering — only log with user's address passes.
	permsNil := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims:     []Claim{ClaimRead},
				EventRules: nil,
			},
		},
	}
	result := FilterEventLogs(
		[]json.RawMessage{logWithUser, logWithoutUser},
		permsNil, []string{userAddr}, nil, nil,
	)
	if len(result) != 1 {
		t.Errorf("nil EventRules: expected 1 log (address-based filter), got %d", len(result))
	}

	// Empty slice EventRules: allowlist mode, nothing allowed.
	permsEmpty := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims:     []Claim{ClaimRead},
				EventRules: []EventRule{},
			},
		},
	}
	result = FilterEventLogs(
		[]json.RawMessage{logWithUser, logWithoutUser},
		permsEmpty, []string{userAddr}, nil, nil,
	)
	if len(result) != 0 {
		t.Errorf("empty EventRules: expected 0 logs (allowlist with nothing), got %d", len(result))
	}
}

func TestFilterEventLogs_EmptyTopicsArray(t *testing.T) {
	// U24: Log with empty topics array is blocked in allowlist mode.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: "0xabc0000000000000000000000000000000000000000000000000000000000000", Name: "SomeEvent"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":[],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs for empty topics array, got %d", len(result))
	}
}

func TestFilterEventLogs_MalformedDataWithParamRules(t *testing.T) {
	// U25: A log with malformed/truncated data field and param_rules should be removed (fail-closed).
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 2, MustBe: "self"}, // value param (non-indexed) — but data is truncated
						},
					},
				},
			},
		},
	}

	// Log with truncated data (not valid ABI encoding for uint256).
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `","` + userTopic + `"],"data":"0xDEAD"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs for malformed data with param_rules (fail-closed), got %d", len(result))
	}
}

func TestFilterEventLogs_MultipleParamRules_OneMatches(t *testing.T) {
	// U31: Multiple ParamRules with OR semantic — user matches one but not other → visible.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	userTopic := "0x000000000000000000000000" + userAddr[2:]
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"}, // from must be self
							{Index: 1, MustBe: "self"}, // OR to must be self
						},
					},
				},
			},
		},
	}

	// User is "to" (index 1) but not "from" (index 0). OR semantic: should pass.
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + userTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (OR semantic, user matches to), got %d", len(result))
	}
}

func TestFilterEventLogs_MultipleParamRules_NoneMatch(t *testing.T) {
	// U32: Multiple ParamRules — neither matches → hidden.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"},
							{Index: 1, MustBe: "self"},
						},
					},
				},
			},
		},
	}

	// User is neither from nor to.
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (neither param matches), got %d", len(result))
	}
}

func TestFilterEventLogs_ParamRuleIndexOutOfRange(t *testing.T) {
	// U33: ParamRule with index out of range → hidden (fail-closed).
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 99, MustBe: "self"}, // way out of range
						},
					},
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `","` + userTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (param index out of range, fail-closed), got %d", len(result))
	}
}

func TestFilterEventLogs_CaseInsensitiveAddressMatching(t *testing.T) {
	// U34: Case-insensitive address matching in topics.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	// User address in lowercase.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	// Topic with UPPERCASE hex for the address portion.
	userTopicUppercase := "0x000000000000000000000000" + "1234567890ABCDEF1234567890ABCDEF12345678"
	otherTopic := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"}, // from must be self
						},
					},
				},
			},
		},
	}

	// User is "from" but the topic uses uppercase hex.
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopicUppercase + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (case-insensitive address match), got %d", len(result))
	}
}

func TestFilterEventLogs_UnionAcrossGrants(t *testing.T) {
	// When ContractAccess has EventRules that are the union of multiple grants,
	// both events should be allowed.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: "0xabc0000000000000000000000000000000000000000000000000000000000000", Name: "EventA"},
					{Topic0: "0xdef0000000000000000000000000000000000000000000000000000000000000", Name: "EventB"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["0xdef0000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["0x1110000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil, nil)
	if len(result) != 2 {
		t.Errorf("expected 2 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_EventRulesNoParamRules_WidensAccess(t *testing.T) {
	// Event rules with no param_rules should widen access beyond address-based
	// filtering: ALL matching events are visible regardless of whether user's
	// address appears in any topic.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherAddr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherTopic1 := "0x000000000000000000000000" + otherAddr1[2:]
	otherTopic2 := "0x000000000000000000000000" + otherAddr2[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"}, // no param_rules
				},
			},
		},
	}

	// Log where user's address does NOT appear in any topic.
	// With event rules (no param_rules), this should PASS because the event is
	// allowlisted without constraints.
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic1 + `","` + otherTopic2 + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (event rules widen access beyond address-based), got %d", len(result))
	}
}

func TestFilterEventLogs_EventRulesWithSelfConstraint(t *testing.T) {
	// Event rules with param_rules "self" constraint: only Transfer events
	// where user is from or to should be visible.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	userTopic := "0x000000000000000000000000" + userAddr[2:]
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"}, // from must be self
							{Index: 1, MustBe: "self"}, // OR to must be self
						},
					},
				},
			},
		},
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	// Log where user is "to" (index 1) — should pass.
	logUserIsTo := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + userTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	// Log where user is neither from nor to — should be hidden.
	logNoUser := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{
		json.RawMessage(logUserIsTo),
		json.RawMessage(logNoUser),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (self constraint filters non-participant), got %d", len(result))
	}
}

func TestFilterEventLogs_NilPerms_FailClosed(t *testing.T) {
	// When perms is nil (user/org resolution failed), all logs must be denied.
	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["0xabc"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, nil, []string{"0xuser"}, nil, nil)
	if len(result) != 0 {
		t.Errorf("nil perms: expected 0 logs (fail-closed), got %d", len(result))
	}
}

// TestContractGrant_JSON_EmptyEventRules verifies that empty event_rules []
// is preserved in JSON serialization (not omitted). This is critical: null means
// "all events visible" while [] means "no events visible" — omitempty would
// silently convert [] to null in API responses.
func TestContractGrant_JSON_EmptyEventRules(t *testing.T) {
	grant := ContractGrant{
		ID:         "test-id",
		ContractID: "contract-id",
		GroupID:    "group-id",
		EventRules: []EventRule{}, // explicitly empty = block all events
	}

	b, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}

	// Must contain "event_rules":[] — NOT omit the field
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}

	raw, ok := m["event_rules"]
	if !ok {
		t.Fatal("event_rules field missing from JSON — omitempty bug")
	}
	if string(raw) != "[]" {
		t.Fatalf("expected event_rules to be [], got %s", string(raw))
	}
}

// TestContractGrant_JSON_NilEventRules verifies that nil event_rules
// serializes as null (all events visible).
func TestContractGrant_JSON_NilEventRules(t *testing.T) {
	grant := ContractGrant{
		ID:         "test-id",
		ContractID: "contract-id",
		GroupID:    "group-id",
		EventRules: nil, // nil = all events visible
	}

	b, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}

	raw, ok := m["event_rules"]
	if !ok {
		t.Fatal("event_rules field missing from JSON")
	}
	if string(raw) != "null" {
		t.Fatalf("expected event_rules to be null, got %s", string(raw))
	}
}

// ---------------------------------------------------------------------------
// U01-U04: IsValidTopic0 validation (supplements event_signatures_test.go)
// ---------------------------------------------------------------------------

func TestIsValidTopic0_Comprehensive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// U01: Valid topic0 (0x + 64 hex chars)
		{"U01_ValidTopic0", "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", true},
		// U02: Too short
		{"U02_TooShort", "0xddf252", false},
		// U03: Non-hex characters
		{"U03_NotHex", "0xZZf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", false},
		// U04: Empty topic0
		{"U04_Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTopic0(tt.input)
			if got != tt.want {
				t.Errorf("IsValidTopic0(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- Custom param value tests ---

func TestFilterEventLogs_CustomHex_IndexedAddress_Match(t *testing.T) {
	// Custom hex value matching on an indexed address param.
	// Event: Transfer(address indexed from, address indexed to, uint256 value)
	// Rule: param[0] must be a specific address.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	targetAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetTopic := "0x000000000000000000000000" + targetAddr[2:]
	otherAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: targetAddr}, // from must be the specific address
						},
					},
				},
			},
		},
	}

	// Log where from matches target address.
	logMatch := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + targetTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	// Log where from does NOT match.
	logNoMatch := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + targetTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{
		json.RawMessage(logMatch),
		json.RawMessage(logNoMatch),
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}
	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, abiProvider, nil)

	if len(result) != 1 {
		t.Errorf("expected 1 log (custom address match on indexed param), got %d", len(result))
	}
}

func TestFilterEventLogs_CustomHex_IndexedUint256_Match(t *testing.T) {
	// Custom hex value matching on an indexed uint256 param.
	// Event: ValueChanged(uint256 indexed id, address indexed setter)
	eventABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "id", "type": "uint256"},
			{"indexed": true, "name": "setter", "type": "address"}
		],
		"name": "ValueChanged",
		"type": "event"
	}]`

	topic0 := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("ValueChanged(uint256,address)")))

	// Target: id must be 42 (0x2a)
	idTopic42 := "0x000000000000000000000000000000000000000000000000000000000000002a"
	idTopic99 := "0x0000000000000000000000000000000000000000000000000000000000000063"
	setterTopic := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: topic0,
						Name:   "ValueChanged",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "0x000000000000000000000000000000000000000000000000000000000000002a"},
						},
					},
				},
			},
		},
	}

	logMatch := `{"address":"0xcontract1","topics":["` + topic0 + `","` + idTopic42 + `","` + setterTopic + `"],"data":"0x"}`
	logNoMatch := `{"address":"0xcontract1","topics":["` + topic0 + `","` + idTopic99 + `","` + setterTopic + `"],"data":"0x"}`

	logs := []json.RawMessage{
		json.RawMessage(logMatch),
		json.RawMessage(logNoMatch),
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": eventABI}}
	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, abiProvider, nil)

	if len(result) != 1 {
		t.Errorf("expected 1 log (custom uint256 match on indexed param), got %d", len(result))
	}
}

func TestFilterEventLogs_CustomHex_Mismatch(t *testing.T) {
	// Custom hex value that does NOT match — event should be filtered out.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	targetAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	actualAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	actualTopic := "0x000000000000000000000000" + actualAddr[2:]
	otherTopic := "0x000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: targetAddr}, // from must be target — but actual is different
						},
					},
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + actualTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (custom value mismatch), got %d", len(result))
	}
}

func TestFilterEventLogs_MixedRules_SelfAndCustom(t *testing.T) {
	// Mixed rules: self + custom value on different params (OR semantics).
	// param[0] must be self OR param[1] must be a specific address.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1111111111111111111111111111111111111111"
	targetToAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetToTopic := "0x000000000000000000000000" + targetToAddr[2:]
	otherAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"},        // from must be caller's address
							{Index: 1, MustBe: targetToAddr},  // OR to must be the specific address
						},
					},
				},
			},
		},
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	// Log 1: user is NOT "from" and "to" IS the target — should pass via custom rule
	log1 := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + targetToTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	// Log 2: user IS "from" but "to" is NOT target — should pass via self rule
	userTopic := "0x000000000000000000000000" + userAddr[2:]
	log2 := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	// Log 3: user is NOT "from" and "to" is NOT target — should be hidden
	log3 := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{
		json.RawMessage(log1),
		json.RawMessage(log2),
		json.RawMessage(log3),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 2 {
		t.Errorf("expected 2 logs (mixed self+custom rules, OR semantics), got %d", len(result))
	}
}

func TestFilterEventLogs_CustomHex_CaseInsensitive(t *testing.T) {
	// Custom address value should match case-insensitively.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	// mustBe in lowercase
	targetAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Topic in mixed case
	targetTopicMixedCase := "0x000000000000000000000000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	otherTopic := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: targetAddr},
						},
					},
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + targetTopicMixedCase + `","` + otherTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, abiProvider, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (case-insensitive custom address match), got %d", len(result))
	}
}

func TestFilterEventLogs_CustomHex_NonIndexedAddress(t *testing.T) {
	// Custom hex value matching on a non-indexed address param (decoded from data).
	// Event: Approval(address indexed owner, address indexed spender, uint256 value)
	// We want to constrain the non-indexed "value" param.
	// Instead, let's use a simpler event: Deposit(address indexed to, uint256 amount, address refundAddr)
	// where refundAddr is non-indexed and we constrain it.
	eventABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "amount", "type": "uint256"},
			{"indexed": false, "name": "refundAddr", "type": "address"}
		],
		"name": "Deposit",
		"type": "event"
	}]`

	// Compute the real topic0 for Deposit(address,uint256,address).
	topic0 := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("Deposit(address,uint256,address)")))

	toTopic := "0x0000000000000000000000001111111111111111111111111111111111111111"
	targetRefund := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// ABI-encoded: amount(uint256)=100 + refundAddr(address)=targetRefund
	// uint256 100 = 0x64
	amountEncoded := "0000000000000000000000000000000000000000000000000000000000000064"
	refundEncoded := "000000000000000000000000" + targetRefund[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: topic0,
						Name:   "Deposit",
						ParamRules: []ParamRule{
							{Index: 2, MustBe: targetRefund}, // refundAddr must be target
						},
					},
				},
			},
		},
	}

	logMatch := `{"address":"0xcontract1","topics":["` + topic0 + `","` + toTopic + `"],"data":"0x` + amountEncoded + refundEncoded + `"}`
	// Log with a different refund address
	wrongRefund := "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	logNoMatch := `{"address":"0xcontract1","topics":["` + topic0 + `","` + toTopic + `"],"data":"0x` + amountEncoded + wrongRefund + `"}`

	logs := []json.RawMessage{
		json.RawMessage(logMatch),
		json.RawMessage(logNoMatch),
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": eventABI}}
	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, abiProvider, nil)

	if len(result) != 1 {
		t.Errorf("expected 1 log (custom address match on non-indexed param), got %d", len(result))
	}
}

func TestFilterEventLogs_CustomHex_ShortFormEquivalence(t *testing.T) {
	// Verify that short-form hex values (0x1) match the same as fully-padded
	// values (0x000...001). The backend uses big.Int comparison for uint types,
	// so these must be treated as equal — not as different byte strings.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	fromTopic := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	toTopic := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Data field: uint256 value = 42 (0x2a), ABI-encoded as 32 bytes
	data := "0x000000000000000000000000000000000000000000000000000000000000002a"

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + fromTopic + `","` + toTopic + `"],"data":"` + data + `"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	// All these short-form values should match the same uint256 value 42
	shortForms := []string{
		"0x2a",                                                               // minimal
		"0x002a",                                                             // extra leading zero byte
		"0x000000000000000000000000000000000000000000000000000000000000002a", // fully padded 32 bytes
	}

	for _, mustBe := range shortForms {
		t.Run("must_be="+mustBe, func(t *testing.T) {
			perms := &EffectivePermissions{
				ContractAccess: map[string]ContractAccess{
					"0xcontract1": {
						Claims: []Claim{ClaimRead},
						EventRules: []EventRule{
							{
								Topic0:     transferTopic0,
								Name:       "Transfer",
								ParamRules: []ParamRule{{Index: 2, MustBe: mustBe}},
							},
						},
					},
				},
			}
			result := FilterEventLogs(logs, perms, []string{"0xunrelated"}, abiProvider, nil)
			if len(result) != 1 {
				t.Errorf("must_be=%s: expected 1 log (value=42 should match), got %d", mustBe, len(result))
			}
		})
	}

	// And a non-matching value to confirm the filter actually works
	t.Run("must_be=0x2b_should_not_match", func(t *testing.T) {
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				"0xcontract1": {
					Claims: []Claim{ClaimRead},
					EventRules: []EventRule{
						{
							Topic0:     transferTopic0,
							Name:       "Transfer",
							ParamRules: []ParamRule{{Index: 2, MustBe: "0x2b"}},
						},
					},
				},
			},
		}
		result := FilterEventLogs(logs, perms, []string{"0xunrelated"}, abiProvider, nil)
		if len(result) != 0 {
			t.Errorf("must_be=0x2b: expected 0 logs (value=42 should NOT match 43), got %d", len(result))
		}
	})
}

func TestFilterEventLogs_CustomHex_Bool(t *testing.T) {
	// Custom bool matching on an indexed bool param.
	eventABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "active", "type": "bool"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "StatusChanged",
		"type": "event"
	}]`

	topic0 := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("StatusChanged(bool,uint256)")))
	trueTopic := "0x0000000000000000000000000000000000000000000000000000000000000001"
	falseTopic := "0x0000000000000000000000000000000000000000000000000000000000000000"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: topic0,
						Name:   "StatusChanged",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "0x01"}, // active must be true
						},
					},
				},
			},
		},
	}

	logTrue := `{"address":"0xcontract1","topics":["` + topic0 + `","` + trueTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	logFalse := `{"address":"0xcontract1","topics":["` + topic0 + `","` + falseTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`

	logs := []json.RawMessage{
		json.RawMessage(logTrue),
		json.RawMessage(logFalse),
	}

	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": eventABI}}
	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, abiProvider, nil)

	if len(result) != 1 {
		t.Errorf("expected 1 log (bool=true match), got %d", len(result))
	}
}

func TestFilterEventLogs_CustomHex_NoABI_FallbackTopicCompare(t *testing.T) {
	// Without ABI, custom hex matching falls back to direct topic comparison.
	topic0 := "0xabc0000000000000000000000000000000000000000000000000000000000000"
	targetValue := "0x000000000000000000000000000000000000000000000000000000000000002a"
	otherValue := "0x0000000000000000000000000000000000000000000000000000000000000063"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: topic0,
						Name:   "SomeEvent",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: targetValue}, // topics[1] must match
						},
					},
				},
			},
		},
	}

	logMatch := `{"address":"0xcontract1","topics":["` + topic0 + `","` + targetValue + `"],"data":"0x"}`
	logNoMatch := `{"address":"0xcontract1","topics":["` + topic0 + `","` + otherValue + `"],"data":"0x"}`

	logs := []json.RawMessage{
		json.RawMessage(logMatch),
		json.RawMessage(logNoMatch),
	}

	// No ABI provider
	result := FilterEventLogs(logs, perms, []string{"0xunrelateduser"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 log (no-ABI fallback topic compare), got %d", len(result))
	}
}

func TestValidateParamRuleMustBe(t *testing.T) {
	tests := []struct {
		name    string
		mustBe  string
		wantOK  bool
	}{
		{"self is valid", "self", true},
		{"valid address hex", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"valid 32-byte hex", "0x000000000000000000000000000000000000000000000000000000000000002a", true},
		{"valid short hex (1 byte)", "0x01", true},
		{"valid bool false", "0x00", true},
		{"empty string", "", false},
		{"no 0x prefix", "aaaa", false},
		{"just 0x", "0x", false},
		{"odd hex chars", "0xaaa", false},
		{"too long (33 bytes)", "0x" + "aa" + "0000000000000000000000000000000000000000000000000000000000000000", false},
		{"invalid hex chars", "0xgggg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := ValidateParamRuleMustBe(tt.mustBe)
			gotOK := errMsg == ""
			if gotOK != tt.wantOK {
				if tt.wantOK {
					t.Errorf("ValidateParamRuleMustBe(%q) returned error %q, want valid", tt.mustBe, errMsg)
				} else {
					t.Errorf("ValidateParamRuleMustBe(%q) returned valid, want error", tt.mustBe)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// U06-U08: ParamRule validation
// Note: There is no standalone ParamRule/EventRule validation function in the
// codebase. Validation happens at the admin API layer (grant create/update).
// These tests document the expected validity of ParamRule values.
// ParamRule{Index: 0, MustBe: "self"} is valid (U06).
// ParamRule{Index: -1, MustBe: "self"} and ParamRule{Index: 0, MustBe: "admin"}
// are invalid (U07, U08), but enforcement is at the API layer, not model layer.
// The filter itself silently ignores unknown MustBe values (safe: fail-closed
// because no match occurs).
// ---------------------------------------------------------------------------

func TestFilterEventLogs_UnknownMustBe_FailClosed(t *testing.T) {
	// U08 behavior at the filter level: an event rule with an unknown MustBe
	// value will never match because checkEventParamRules skips non-"self" rules,
	// meaning no param rule matches and the log is hidden (fail-closed).
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "admin"}, // unknown constraint
						},
					},
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `","` + userTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("U08: unknown MustBe should fail-closed, expected 0 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_NegativeParamIndex_FailClosed(t *testing.T) {
	// U07 behavior at the filter level: negative index is out of range, so
	// matchesParamSelf returns false → log hidden.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: -1, MustBe: "self"}, // negative index
						},
					},
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `","` + userTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("U07: negative param index should fail-closed, expected 0 logs, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// U13: Anonymous event extraction from ABI
// ---------------------------------------------------------------------------

func TestExtractEventSignatures_AnonymousEvent(t *testing.T) {
	// U13: Anonymous events in ABI should be extracted. The go-ethereum ABI
	// parser marks them as Anonymous but still computes a topic0 from the
	// signature (the actual topic0 won't appear in logs for anonymous events).
	abiJSON := `[
		{
			"anonymous": true,
			"inputs": [
				{"indexed": false, "name": "amount", "type": "uint256"}
			],
			"name": "Deposit",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "from", "type": "address"},
				{"indexed": false, "name": "value", "type": "uint256"}
			],
			"name": "Transfer",
			"type": "event"
		}
	]`

	sigs, err := ExtractEventSignatures(abiJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// go-ethereum's ABI parser includes anonymous events in Events map.
	// Both should be extracted.
	if len(sigs) < 1 {
		t.Fatalf("expected at least 1 event signature, got %d", len(sigs))
	}

	// Find Deposit (anonymous)
	var depositFound bool
	for _, sig := range sigs {
		if sig.Name == "Deposit" {
			depositFound = true
			// The signature should still have a valid topic0 (from keccak256 of sig).
			if !IsValidTopic0(sig.Topic0) {
				t.Errorf("anonymous event Deposit should have valid topic0, got %q", sig.Topic0)
			}
			break
		}
	}
	if !depositFound {
		t.Error("anonymous event Deposit not found in extracted signatures")
	}
}

// ---------------------------------------------------------------------------
// U21: Allowlist_MixedLogs — 3 logs, only 1 event type allowed
// ---------------------------------------------------------------------------

func TestFilterEventLogs_Allowlist_MixedLogs(t *testing.T) {
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
	customTopic0 := "0x1111111111111111111111111111111111111111111111111111111111111111"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + customTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("U21: expected 1 log (only Transfer), got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// U23: Anonymous_Allowed — no AllowAnonymous field exists in the model.
// AllowAnonymous is NOT implemented in the EventRule model. Anonymous events
// (no topic0) are always blocked in allowlist mode. This test documents the
// current behavior. If AllowAnonymous is added later, this test should be
// updated.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// U28-U30: Non-indexed param matching
// ---------------------------------------------------------------------------

func TestFilterEventLogs_NonIndexedParam_Match(t *testing.T) {
	// U28: Non-indexed address param matches user → visible.
	// CustomEvent(uint256 indexed id, address recipient) — recipient is non-indexed.
	customEventABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "id", "type": "uint256"},
			{"indexed": false, "name": "recipient", "type": "address"}
		],
		"name": "CustomEvent",
		"type": "event"
	}]`

	sigs, err := ExtractEventSignatures(customEventABI)
	if err != nil {
		t.Fatalf("failed to extract sigs: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	customTopic0 := sigs[0].Topic0

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	// ABI-encode the user address as the data field (non-indexed param, 32-byte padded).
	userAddrPadded := "000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: customTopic0,
						Name:   "CustomEvent",
						ParamRules: []ParamRule{
							{Index: 1, MustBe: "self"}, // recipient (non-indexed, param index 1)
						},
					},
				},
			},
		},
	}

	// id=42 in topics[1], recipient in data
	idTopic := "0x000000000000000000000000000000000000000000000000000000000000002a"
	logJSON := `{"address":"0xcontract1","topics":["` + customTopic0 + `","` + idTopic + `"],"data":"0x` + userAddrPadded + `"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": customEventABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 1 {
		t.Errorf("U28: non-indexed address param matches user, expected 1 log, got %d", len(result))
	}
}

func TestFilterEventLogs_NonIndexedParam_NoMatch(t *testing.T) {
	// U29: Non-indexed address param doesn't match user → hidden.
	customEventABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "id", "type": "uint256"},
			{"indexed": false, "name": "recipient", "type": "address"}
		],
		"name": "CustomEvent",
		"type": "event"
	}]`

	sigs, err := ExtractEventSignatures(customEventABI)
	if err != nil {
		t.Fatalf("failed to extract sigs: %v", err)
	}
	customTopic0 := sigs[0].Topic0

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherAddrPadded := "000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: customTopic0,
						Name:   "CustomEvent",
						ParamRules: []ParamRule{
							{Index: 1, MustBe: "self"},
						},
					},
				},
			},
		},
	}

	idTopic := "0x000000000000000000000000000000000000000000000000000000000000002a"
	logJSON := `{"address":"0xcontract1","topics":["` + customTopic0 + `","` + idTopic + `"],"data":"0x` + otherAddrPadded + `"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": customEventABI}}

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("U29: non-indexed param doesn't match user, expected 0 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_NonIndexedParam_NoABI_FailClosed(t *testing.T) {
	// U30: No ABI available, param rule on non-indexed param → hidden (fail-closed).
	// Without ABI, matchesParamSelf falls back to topic position guess.
	// For a non-indexed param, the topic position won't have the right data.
	customTopic0 := "0x1111111111111111111111111111111111111111111111111111111111111111"

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userAddrPadded := "000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: customTopic0,
						Name:   "CustomEvent",
						ParamRules: []ParamRule{
							// Index 1 is a non-indexed param in reality, but without ABI
							// the filter can't decode data. If there's no topics[2], it
							// falls back to false.
							{Index: 1, MustBe: "self"},
						},
					},
				},
			},
		},
	}

	// Only 1 topic beyond topic0 (the indexed "id"), no topics[2] for param index 1
	idTopic := "0x000000000000000000000000000000000000000000000000000000000000002a"
	logJSON := `{"address":"0xcontract1","topics":["` + customTopic0 + `","` + idTopic + `"],"data":"0x` + userAddrPadded + `"}`

	logs := []json.RawMessage{json.RawMessage(logJSON)}
	// No ABI provider
	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 0 {
		t.Errorf("U30: no ABI with non-indexed param rule should fail-closed, expected 0 logs, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// U36-U40: Union edge cases (tests for unionEventRules)
// ---------------------------------------------------------------------------

func TestUnionEventRules_OneNil_OneRestricted(t *testing.T) {
	// U36: Grant A has rules [Transfer], Grant B has nil → unrestricted wins.
	a := []EventRule{
		{Topic0: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", Name: "Transfer"},
	}
	var b []EventRule // nil

	result := unionEventRules(a, b)
	if result != nil {
		t.Errorf("U36: nil + restricted should yield nil (unrestricted), got %v", result)
	}

	// Also test reversed order.
	result = unionEventRules(b, a)
	if result != nil {
		t.Errorf("U36 reversed: restricted + nil should yield nil (unrestricted), got %v", result)
	}
}

func TestUnionEventRules_BothNil(t *testing.T) {
	// U37: Both grants nil → all visible (nil).
	result := unionEventRules(nil, nil)
	if result != nil {
		t.Errorf("U37: nil + nil should yield nil, got %v", result)
	}
}

func TestUnionEventRules_SameEvent_BothParams(t *testing.T) {
	// U39: Same event, Grant A: param 0 self, Grant B: param 1 self.
	// Current implementation: when both have param rules, keeps existing (Grant A).
	// This means only param 0 self is checked. The filter itself uses OR semantics
	// within a single rule's ParamRules, so ideally the union should merge both
	// param rules. This test documents current behavior.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	a := []EventRule{
		{
			Topic0:     transferTopic0,
			Name:       "Transfer",
			ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
		},
	}
	b := []EventRule{
		{
			Topic0:     transferTopic0,
			Name:       "Transfer",
			ParamRules: []ParamRule{{Index: 1, MustBe: "self"}},
		},
	}

	result := unionEventRules(a, b)
	if result == nil {
		t.Fatal("U39: expected non-nil result")
	}
	if len(result) != 1 {
		t.Fatalf("U39: expected 1 rule, got %d", len(result))
	}

	// Current behavior: keeps Grant A's param rules (arbitrary but consistent).
	// Both param rules should ideally be present for true OR semantics across grants.
	// Document this as the current behavior; a future fix could merge param rules.
	rule := result[0]
	if !strings.EqualFold(rule.Topic0, transferTopic0) {
		t.Errorf("U39: expected topic0 %s, got %s", transferTopic0, rule.Topic0)
	}
	// The rule should have param rules (not nil/empty — that would mean unrestricted).
	if len(rule.ParamRules) == 0 {
		t.Error("U39: expected param rules on merged rule, got none (would mean unrestricted)")
	}
}

func TestUnionEventRules_EmptySlice_vs_Rules(t *testing.T) {
	// U40: Grant A: [] (empty), Grant B: [Transfer] → Transfer visible.
	// Empty slice means "deny all". Union with [Transfer] = [Transfer].
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	a := []EventRule{} // deny all
	b := []EventRule{
		{Topic0: transferTopic0, Name: "Transfer"},
	}

	result := unionEventRules(a, b)
	if result == nil {
		t.Fatal("U40: expected non-nil result (not unrestricted)")
	}
	if len(result) != 1 {
		t.Fatalf("U40: expected 1 rule (Transfer), got %d", len(result))
	}
	if !strings.EqualFold(result[0].Topic0, transferTopic0) {
		t.Errorf("U40: expected Transfer topic0, got %s", result[0].Topic0)
	}
}

func TestUnionEventRules_SameEvent_OneNoParams(t *testing.T) {
	// U38: Grant A: Transfer + self, Grant B: Transfer (no params).
	// Union should pick the less restrictive: Transfer with no params.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	a := []EventRule{
		{
			Topic0:     transferTopic0,
			Name:       "Transfer",
			ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
		},
	}
	b := []EventRule{
		{Topic0: transferTopic0, Name: "Transfer"}, // no param rules = less restrictive
	}

	result := unionEventRules(a, b)
	if result == nil {
		t.Fatal("U38: expected non-nil result")
	}
	if len(result) != 1 {
		t.Fatalf("U38: expected 1 rule, got %d", len(result))
	}
	if len(result[0].ParamRules) != 0 {
		t.Errorf("U38: expected no param rules (less restrictive wins), got %d", len(result[0].ParamRules))
	}
}

func TestUnionEventRules_DifferentEvents(t *testing.T) {
	// U35: Grant A: Transfer, Grant B: Approval → union = both.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	a := []EventRule{{Topic0: transferTopic0, Name: "Transfer"}}
	b := []EventRule{{Topic0: approvalTopic0, Name: "Approval"}}

	result := unionEventRules(a, b)
	if result == nil {
		t.Fatal("U35: expected non-nil result")
	}
	if len(result) != 2 {
		t.Fatalf("U35: expected 2 rules (Transfer + Approval), got %d", len(result))
	}

	topics := make(map[string]bool)
	for _, r := range result {
		topics[strings.ToLower(r.Topic0)] = true
	}
	if !topics[transferTopic0] {
		t.Error("U35: Transfer missing from union")
	}
	if !topics[approvalTopic0] {
		t.Error("U35: Approval missing from union")
	}
}

// ---------------------------------------------------------------------------
// U41-U45: HasEventAccess / GetEventRule helpers
// Note: There is no HasEventAccess function in the codebase. The closest is
// GetEventRules on EffectivePermissions and the eventAllowed internal function.
// We test the effective behavior through GetEventRules and FilterEventLogs.
// ---------------------------------------------------------------------------

func TestGetEventRules_NilUnrestricted(t *testing.T) {
	// U41: nil EventRules means unrestricted — true for any topic0.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil,
			},
		},
	}

	rules := perms.GetEventRules("0xcontract1")
	if rules != nil {
		t.Errorf("U41: nil EventRules should return nil (unrestricted), got %v", rules)
	}
}

func TestGetEventRules_EmptyDenyAll(t *testing.T) {
	// U42: empty slice means deny all — false for any topic0.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: []EventRule{},
			},
		},
	}

	rules := perms.GetEventRules("0xcontract1")
	if rules == nil {
		t.Fatal("U42: empty EventRules should return non-nil empty slice, got nil")
	}
	if len(rules) != 0 {
		t.Errorf("U42: expected empty slice, got %d rules", len(rules))
	}
}

func TestGetEventRules_PopulatedAllowlist(t *testing.T) {
	// U43: Populated rules — acts as allowlist.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
				},
			},
		},
	}

	rules := perms.GetEventRules("0xcontract1")
	if len(rules) != 1 {
		t.Fatalf("U43: expected 1 rule, got %d", len(rules))
	}
	if rules[0].Topic0 != transferTopic0 {
		t.Errorf("U43: expected Transfer topic0, got %s", rules[0].Topic0)
	}
}

func TestGetEventRules_FindByTopic0(t *testing.T) {
	// U44-U45: GetEventRule (find by topic0) — no dedicated function exists,
	// but we can search the returned slice.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				},
			},
		},
	}

	rules := perms.GetEventRules("0xcontract1")

	// U44: Found — Transfer with ParamRules
	var found *EventRule
	for i := range rules {
		if strings.EqualFold(rules[i].Topic0, transferTopic0) {
			found = &rules[i]
			break
		}
	}
	if found == nil {
		t.Fatal("U44: Transfer rule not found by topic0")
	}
	if len(found.ParamRules) != 1 {
		t.Errorf("U44: expected 1 param rule, got %d", len(found.ParamRules))
	}

	// U45: Not found — Approval topic0 not in rules
	var notFound *EventRule
	for i := range rules {
		if strings.EqualFold(rules[i].Topic0, approvalTopic0) {
			notFound = &rules[i]
			break
		}
	}
	if notFound != nil {
		t.Error("U45: Approval should not be found in rules")
	}
}

// ---------------------------------------------------------------------------
// I28-I30: Admin bypass / no bypass for event rules
// ---------------------------------------------------------------------------

func TestFilterEventLogs_AdminClaim_Bypass(t *testing.T) {
	// I28: Admin claim on contract bypasses event_rules — admin sees ALL logs.
	// Previously this was a documented gap (admin claim did not bypass event
	// rules). Now FilterEventLogs checks Claims for ClaimAdmin and short-circuits.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimAdmin, ClaimRead, ClaimWrite, ClaimDeploy}, // admin!
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
					// Approval is NOT in the allowlist — but admin bypasses
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)

	// Admin bypass: both logs should be visible regardless of event rules.
	if len(result) != 2 {
		t.Errorf("I28: admin claim should bypass event rules, expected 2 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_OrgAdmin_Bypass(t *testing.T) {
	// I29: Org admin gets AllClaims() (including ClaimAdmin) from the resolver
	// (computeOrgAdminPermissions). The admin bypass in FilterEventLogs means
	// org admins see ALL logs, regardless of event rules or address-in-topics.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	// Org admin permissions: all claims (including admin), nil EventRules
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     AllClaims(),
				EventRules: nil, // org admin: no restrictions
			},
		},
	}

	// User address NOT in any topics — admin bypass means this doesn't matter.
	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `","` + otherTopic + `"],"data":"0x"}`),
	}

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 2 {
		t.Errorf("I29: org admin should see all logs via admin bypass, expected 2, got %d", len(result))
	}
}

func TestFilterEventLogs_ReadClaim_NoByppass(t *testing.T) {
	// I30: User with only read claim + event_rules [Transfer] → only Transfer visible.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("I30: read claim should not bypass event_rules, expected 1 log, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// I25-I27: Cross-org isolation (unit-level simulation)
// Full cross-org isolation requires the AccessController + DB. These tests
// simulate the permissions that the resolver would produce.
// ---------------------------------------------------------------------------

func TestFilterEventLogs_CrossOrg_NoAccess(t *testing.T) {
	// I25: User in Org Alpha has no grant on Org Beta's contract → no logs.
	// The resolver would not include Org Beta's contract in ContractAccess.
	betaContractAddr := "0x6666666666666666666666666666666666666666"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			// Only Alpha's contract
			"0x5555555555555555555555555555555555555555": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil,
			},
			// No entry for Beta's contract
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"` + betaContractAddr + `","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xaaaa"}, nil, nil)
	if len(result) != 0 {
		t.Errorf("I25: cross-org contract should be invisible, expected 0 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_MultipleContracts_PartialAccess(t *testing.T) {
	// I26: User has grants on contracts X and Z but not Y → only X and Z logs.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	userAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontractx": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil, // unrestricted
			},
			"0xcontractz": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil,
			},
			// No entry for 0xcontracty
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontractx","topics":["` + transferTopic0 + `","` + userTopic + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontracty","topics":["` + transferTopic0 + `","` + userTopic + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontractz","topics":["` + transferTopic0 + `","` + userTopic + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 2 {
		t.Errorf("I26: expected 2 logs (X and Z), got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// Viewer-role dimension tests: sender, receiver, 3rd party
// ---------------------------------------------------------------------------

func TestFilterEventLogs_ViewerDimension_SenderSeesOwnTransfer(t *testing.T) {
	// Sender with event_rules: [Transfer] sees Transfer they sent.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	senderAddr := "0x1234567890abcdef1234567890abcdef12345678"
	receiverAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	senderTopic := "0x000000000000000000000000" + senderAddr[2:]
	receiverTopic := "0x000000000000000000000000" + receiverAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"}, // from must be self
							{Index: 1, MustBe: "self"}, // OR to must be self
						},
					},
				},
			},
		},
	}

	// Sender is "from" (topics[1])
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + senderTopic + `","` + receiverTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{senderAddr}, abiProvider, nil)
	if len(result) != 1 {
		t.Errorf("ViewerDimension: sender should see Transfer they sent, expected 1, got %d", len(result))
	}
}

func TestFilterEventLogs_ViewerDimension_ReceiverDeniedBySelfOnFrom(t *testing.T) {
	// Receiver with event_rules: [Transfer, self on from] does NOT see Transfer
	// (from != self). Only "from" constraint, no "to" constraint.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	receiverAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	senderAddr := "0x1234567890abcdef1234567890abcdef12345678"
	senderTopic := "0x000000000000000000000000" + senderAddr[2:]
	receiverTopic := "0x000000000000000000000000" + receiverAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"}, // ONLY from must be self (no "to" constraint)
						},
					},
				},
			},
		},
	}

	// Receiver is "to" (topics[2]), but only "from" (index 0) has self constraint
	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + senderTopic + `","` + receiverTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{receiverAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("ViewerDimension: receiver should NOT see Transfer (from != self), expected 0, got %d", len(result))
	}
}

func TestFilterEventLogs_ViewerDimension_ThirdParty_NoParamMatch(t *testing.T) {
	// 3rd party with grant but no param match → blocked by param rule.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	erc20ABI := `[{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}]`

	thirdPartyAddr := "0xcccccccccccccccccccccccccccccccccccccccc"
	senderAddr := "0x1111111111111111111111111111111111111111"
	receiverAddr := "0x2222222222222222222222222222222222222222"
	senderTopic := "0x000000000000000000000000" + senderAddr[2:]
	receiverTopic := "0x000000000000000000000000" + receiverAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []ParamRule{
							{Index: 0, MustBe: "self"},
							{Index: 1, MustBe: "self"},
						},
					},
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + senderTopic + `","` + receiverTopic + `"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}
	abiProvider := &testABIProvider{abis: map[string]string{"0xcontract1": erc20ABI}}

	result := FilterEventLogs(logs, perms, []string{thirdPartyAddr}, abiProvider, nil)
	if len(result) != 0 {
		t.Errorf("ViewerDimension: 3rd party with no param match should be blocked, expected 0, got %d", len(result))
	}
}

func TestFilterEventLogs_ViewerDimension_ThirdParty_NoParamRules(t *testing.T) {
	// 3rd party with grant and no param rules → sees event (event allowed,
	// no further constraint).
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	thirdPartyAddr := "0xcccccccccccccccccccccccccccccccccccccccc"
	senderTopic := "0x0000000000000000000000001111111111111111111111111111111111111111"
	receiverTopic := "0x0000000000000000000000002222222222222222222222222222222222222222"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"}, // no param rules
				},
			},
		},
	}

	logJSON := `{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + senderTopic + `","` + receiverTopic + `"],"data":"0x"}`
	logs := []json.RawMessage{json.RawMessage(logJSON)}

	result := FilterEventLogs(logs, perms, []string{thirdPartyAddr}, nil, nil)
	if len(result) != 1 {
		t.Errorf("ViewerDimension: 3rd party with no param rules should see allowed event, expected 1, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// Union across grants: E2E simulation through FilterEventLogs
// ---------------------------------------------------------------------------

func TestFilterEventLogs_UnionGrants_UnrestrictedWins(t *testing.T) {
	// U36 applied to filtering: when effective permissions have nil EventRules
	// (because one grant was unrestricted), all logs with user's address pass.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	// After union: nil (unrestricted) wins
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil, // result of union where one grant was nil
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `","` + userTopic + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 2 {
		t.Errorf("Union unrestricted: expected 2 logs (all with user address), got %d", len(result))
	}
}

func TestFilterEventLogs_UnionGrants_BothRestricted(t *testing.T) {
	// After union of [Transfer] and [Approval] → both should be visible.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
	customTopic0 := "0x1111111111111111111111111111111111111111111111111111111111111111"

	// Union result of two restricted grants
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
					{Topic0: approvalTopic0, Name: "Approval"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + customTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 2 {
		t.Errorf("Union both restricted: expected 2 logs (Transfer + Approval), got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// Utility: Verify hex encoding helpers used in tests
// ---------------------------------------------------------------------------

func TestHexEncodingConsistency(t *testing.T) {
	// Ensure our test address padding matches what the EVM produces.
	addr := "1234567890abcdef1234567890abcdef12345678"
	padded := "000000000000000000000000" + addr
	if len(padded) != 64 {
		t.Fatalf("padded address should be 64 hex chars, got %d", len(padded))
	}
	_, err := hex.DecodeString(padded)
	if err != nil {
		t.Fatalf("padded address is not valid hex: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RD-751: Admin bypass for log filtering
// ---------------------------------------------------------------------------

func TestFilterEventLogs_AdminSeesAllLogs_NoAddressInTopics(t *testing.T) {
	// Admin user should see ALL logs from their contract even when their address
	// does NOT appear in any topic. This is the primary RD-751 requirement.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
	customTopic0 := "0x1111111111111111111111111111111111111111111111111111111111111111"

	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimAdmin, ClaimRead, ClaimWrite, ClaimDeploy, ClaimUpgrade},
				EventRules: nil, // no event rules = would normally require address in topics
			},
		},
	}

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"

	// None of these logs contain the user's address in topics.
	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + otherTopic + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `","` + otherTopic + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + customTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 3 {
		t.Errorf("admin should see all 3 logs without address in topics, got %d", len(result))
	}
}

func TestFilterEventLogs_ReadUser_NoAddressInTopics_Filtered(t *testing.T) {
	// A user with only the read claim (no admin) should NOT see logs when their
	// address does not appear in topics and no event rules are configured.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil, // default address-based filtering
			},
		},
	}

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + otherTopic + `","` + otherTopic + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 0 {
		t.Errorf("read user without address in topics should see 0 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_AdminBypassWithEventRulesStillSeesAll(t *testing.T) {
	// Admin claim overrides event rules: even with restrictive event rules that
	// would normally filter some logs, an admin sees everything.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
	customTopic0 := "0x1111111111111111111111111111111111111111111111111111111111111111"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimAdmin, ClaimRead, ClaimWrite},
				EventRules: []EventRule{
					// Only Transfer is in the allowlist — but admin bypasses
					{Topic0: transferTopic0, Name: "Transfer"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + customTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 3 {
		t.Errorf("admin should bypass event rules and see all 3 logs, got %d", len(result))
	}
}

func TestFilterEventLogs_AdminBypassWithEmptyEventRules(t *testing.T) {
	// Empty event rules [] means "deny all events". But admin bypass still
	// overrides this and sees everything.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimAdmin, ClaimRead},
				EventRules: []EventRule{}, // deny all — but admin overrides
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("admin should bypass empty event rules, expected 1, got %d", len(result))
	}
}

func TestFilterEventLogs_AdminOnOneContract_ReadOnAnother(t *testing.T) {
	// Admin bypass should only apply to the contract the user has admin claim on.
	// On other contracts, normal filtering still applies.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract_admin": {
				Claims:     []Claim{ClaimAdmin, ClaimRead},
				EventRules: nil, // no rules
			},
			"0xcontract_read": {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
				},
			},
		},
	}

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"

	logs := []json.RawMessage{
		// Admin contract — user address NOT in topics. Admin bypass: visible.
		json.RawMessage(`{"address":"0xcontract_admin","topics":["` + transferTopic0 + `","` + otherTopic + `"],"data":"0x"}`),
		// Read contract — Approval event NOT in allowlist. Normal filtering: blocked.
		json.RawMessage(`{"address":"0xcontract_read","topics":["` + approvalTopic0 + `","` + otherTopic + `"],"data":"0x"}`),
		// Read contract — Transfer event in allowlist. Normal filtering: passed.
		json.RawMessage(`{"address":"0xcontract_read","topics":["` + transferTopic0 + `","` + otherTopic + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 2 {
		t.Errorf("expected 2 logs (admin contract + allowed event on read contract), got %d", len(result))
	}
}

func TestFilterEventLogs_CrossOrgIsolation_NoAccessToOtherOrg(t *testing.T) {
	// Verify that cross-org isolation works: a user with no access to a contract
	// (simulating a contract in another org) sees zero logs from it.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userTopic := "0x000000000000000000000000" + userAddr[2:]

	// User only has access to contract1 (their org). No entry for contract_other_org.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil,
			},
			// 0xcontract_other_org is NOT in ContractAccess → no access
		},
	}

	logs := []json.RawMessage{
		// Own contract — user address in topic → visible.
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `","` + userTopic + `"],"data":"0x"}`),
		// Other org's contract — even though user address appears in topic → hidden.
		json.RawMessage(`{"address":"0xcontract_other_org","topics":["` + transferTopic0 + `","` + userTopic + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(result) != 1 {
		t.Errorf("cross-org isolation: expected 1 log (own contract only), got %d", len(result))
	}
}

func TestFilterEventLogs_AdminBypassWithAnonymousEvent(t *testing.T) {
	// Admin bypass should include anonymous events (no topic0) which would
	// normally be blocked in allowlist mode.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimAdmin, ClaimRead},
				EventRules: []EventRule{
					{Topic0: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", Name: "Transfer"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		// Anonymous event (no topics)
		json.RawMessage(`{"address":"0xcontract1","topics":[],"data":"0xdeadbeef"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("admin should bypass and see anonymous events, expected 1, got %d", len(result))
	}
}

func TestFilterEventLogs_DeployWriteClaims_NoBypass(t *testing.T) {
	// Users with deploy or write claims (but NOT admin) should NOT get the
	// admin bypass. Only the admin claim triggers the bypass.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims: []Claim{ClaimRead, ClaimWrite, ClaimDeploy, ClaimUpgrade},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["` + transferTopic0 + `"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["` + approvalTopic0 + `"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("deploy/write user should NOT get admin bypass, expected 1 log, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// logVisibleTo extension tests
// ---------------------------------------------------------------------------

func TestFilterEventLogs_LogVisibleTo_ParamRulesFail_ViewerInList(t *testing.T) {
	// Viewer DID is in logVisibleTo list → event visible despite must_be=self failure.
	contractAddr := "0xcontract1"
	userAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	viewerDID := "did:privado:viewer1"
	txHash := "0xdeadbeef"

	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	// Topic1 = from addr (not the viewer's address)
	otherTopic := "0x000000000000000000000000" + otherAddr[2:]

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer", ParamRules: []ParamRule{
						{Index: 0, MustBe: "self"},
					}},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"` + contractAddr + `","topics":["` + transferTopic0 + `","` + otherTopic + `"],"data":"0x","transactionHash":"` + txHash + `"}`),
	}

	visCtx := &LogVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			txHash: {viewerDID, "did:privado:other"},
		},
	}

	// Without visCtx: should be filtered (must_be=self fails)
	resultWithout := FilterEventLogs(logs, perms, []string{userAddr}, nil, nil)
	if len(resultWithout) != 0 {
		t.Errorf("without visCtx: expected 0 logs (self check fails), got %d", len(resultWithout))
	}

	// With visCtx: should pass (viewer in logVisibleTo)
	resultWith := FilterEventLogs(logs, perms, []string{userAddr}, nil, visCtx)
	if len(resultWith) != 1 {
		t.Errorf("with visCtx: expected 1 log (viewer in logVisibleTo), got %d", len(resultWith))
	}
}

func TestFilterEventLogs_LogVisibleTo_ViewerNotInList(t *testing.T) {
	// Viewer DID NOT in logVisibleTo list → event still filtered.
	contractAddr := "0xcontract1"
	viewerDID := "did:privado:not_listed"
	txHash := "0xdeadbeef"

	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	otherTopic := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer", ParamRules: []ParamRule{
						{Index: 0, MustBe: "self"},
					}},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"` + contractAddr + `","topics":["` + transferTopic0 + `","` + otherTopic + `"],"data":"0x","transactionHash":"` + txHash + `"}`),
	}

	visCtx := &LogVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			txHash: {"did:privado:someone_else"},
		},
	}

	result := FilterEventLogs(logs, perms, []string{"0xnotinanylog"}, nil, visCtx)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (viewer not in logVisibleTo list), got %d", len(result))
	}
}

func TestFilterEventLogs_LogVisibleTo_NilContext_BackwardCompat(t *testing.T) {
	// nil visCtx → backward compat, no change in behavior.
	contractAddr := "0xcontract1"
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	otherTopic := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer", ParamRules: []ParamRule{
						{Index: 0, MustBe: "self"},
					}},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"` + contractAddr + `","topics":["` + transferTopic0 + `","` + otherTopic + `"],"data":"0x","transactionHash":"0xabc"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xnotinanylog"}, nil, nil)
	if len(result) != 0 {
		t.Errorf("nil visCtx: expected 0 logs (backward compat), got %d", len(result))
	}
}

func TestFilterEventLogs_LogVisibleTo_DoesNotBypassTopic0Allowlist(t *testing.T) {
	// logVisibleTo should NOT bypass topic0 allowlist — only param rules.
	contractAddr := "0xcontract1"
	viewerDID := "did:privado:viewer1"
	txHash := "0xdeadbeef"

	allowedTopic0 := "0xaaa0000000000000000000000000000000000000000000000000000000000000"
	disallowedTopic0 := "0xbbb0000000000000000000000000000000000000000000000000000000000000"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims: []Claim{ClaimRead},
				EventRules: []EventRule{
					{Topic0: allowedTopic0, Name: "AllowedEvent"},
				},
			},
		},
	}

	logs := []json.RawMessage{
		// Disallowed topic0 — logVisibleTo should NOT make this pass.
		json.RawMessage(`{"address":"` + contractAddr + `","topics":["` + disallowedTopic0 + `"],"data":"0x","transactionHash":"` + txHash + `"}`),
	}

	visCtx := &LogVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			txHash: {viewerDID},
		},
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil, visCtx)
	if len(result) != 0 {
		t.Errorf("expected 0 logs (logVisibleTo must not bypass topic0 allowlist), got %d", len(result))
	}
}

func TestFilterEventLogs_LogVisibleTo_AdminStillBypasses(t *testing.T) {
	// Admin users bypass everything — logVisibleTo doesn't change this.
	contractAddr := "0xcontract1"
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims: []Claim{ClaimAdmin},
				EventRules: []EventRule{
					{Topic0: transferTopic0, Name: "Transfer", ParamRules: []ParamRule{
						{Index: 0, MustBe: "self"},
					}},
				},
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"` + contractAddr + `","topics":["` + transferTopic0 + `","0x0000000000000000000000000000000000000000000000000000000000000000"],"data":"0x","transactionHash":"0xabc"}`),
	}

	// Admin sees everything regardless of visCtx.
	result := FilterEventLogs(logs, perms, []string{"0xadmin"}, nil, nil)
	if len(result) != 1 {
		t.Errorf("admin should see all logs, expected 1, got %d", len(result))
	}
}

func TestFilterEventLogs_LogVisibleTo_DefaultAddressFilter_FallbackToVisibleTo(t *testing.T) {
	// When no event rules are configured (default address filtering),
	// logVisibleTo extends the filter: if user address is NOT in topics
	// but viewer DID IS in logVisibleTo, the log should be visible.
	contractAddr := "0xcontract1"
	viewerDID := "did:privado:viewer1"
	txHash := "0xdeadbeef"
	eventSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	otherTopic := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims:     []Claim{ClaimRead},
				EventRules: nil, // default address filtering
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"` + contractAddr + `","topics":["` + eventSig + `","` + otherTopic + `"],"data":"0x","transactionHash":"` + txHash + `"}`),
	}

	// Without visCtx: should be hidden (address not in topics)
	resultWithout := FilterEventLogs(logs, perms, []string{"0xnotintopics"}, nil, nil)
	if len(resultWithout) != 0 {
		t.Errorf("without visCtx: expected 0 logs, got %d", len(resultWithout))
	}

	// With visCtx: should be visible (viewer in logVisibleTo)
	visCtx := &LogVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			txHash: {viewerDID},
		},
	}
	resultWith := FilterEventLogs(logs, perms, []string{"0xnotintopics"}, nil, visCtx)
	if len(resultWith) != 1 {
		t.Errorf("with visCtx: expected 1 log (viewer in logVisibleTo), got %d", len(resultWith))
	}
}
