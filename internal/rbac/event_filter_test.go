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

func TestFilterEventLogs_NoEventRules(t *testing.T) {
	// When no event rules are configured, all logs pass through.
	perms := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {
				Claims:     []Claim{ClaimRead},
				EventRules: nil, // no event rules = all events visible
			},
		},
	}

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["0xabc"],"data":"0x"}`),
		json.RawMessage(`{"address":"0xcontract1","topics":["0xdef"],"data":"0x"}`),
	}

	result := FilterEventLogs(logs, perms, []string{"0xuser1"}, nil)
	if len(result) != 2 {
		t.Errorf("expected 2 logs, got %d", len(result))
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
	// U17: nil EventRules means "no filtering" (all events pass through).
	// Empty slice [] means "allowlist mode with nothing allowed" (all events blocked).
	contractAddr := "0xcontract1"

	logs := []json.RawMessage{
		json.RawMessage(`{"address":"0xcontract1","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000"],"data":"0x"}`),
	}

	// nil EventRules: all events pass through.
	permsNil := &EffectivePermissions{
		ContractAccess: map[string]ContractAccess{
			contractAddr: {
				Claims:     []Claim{ClaimRead},
				EventRules: nil,
			},
		},
	}
	result := FilterEventLogs(logs, permsNil, []string{"0xuser"}, nil)
	if len(result) != 1 {
		t.Errorf("nil EventRules: expected 1 log (pass-through), got %d", len(result))
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
	result = FilterEventLogs(logs, permsEmpty, []string{"0xuser"}, nil)
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
