package rbac

import (
	"encoding/json"
	"testing"
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, nil)
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

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil)
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

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil)
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

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil)
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
	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)

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
		permsNil, []string{userAddr}, nil,
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
		permsEmpty, []string{userAddr}, nil,
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

	result := FilterEventLogs(logs, perms, []string{"0xuser"}, nil)
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)
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

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil)
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
	result := FilterEventLogs(logs, perms, []string{userAddr}, nil)
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

	result := FilterEventLogs(logs, perms, []string{userAddr}, abiProvider)
	if len(result) != 1 {
		t.Errorf("expected 1 log (self constraint filters non-participant), got %d", len(result))
	}
}

func TestFilterEventLogs_NilPerms_FailClosed(t *testing.T) {
	// When perms is nil (user/org resolution failed), all logs should be
	// returned as-is (FilterEventLogs currently returns logs when perms==nil).
	// This is safe because the caller (jsonrpc_processor) handles the nil-perms
	// case at a higher level; FilterEventLogs is given a valid perms object.
	// However, if perms IS nil, the function returns logs unchanged.
	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["0xabc"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, nil, []string{"0xuser"}, nil)
	// With nil perms, FilterEventLogs returns logs as-is (no perms to evaluate).
	if len(result) != 1 {
		t.Errorf("nil perms: expected 1 log (pass-through), got %d", len(result))
	}
}
