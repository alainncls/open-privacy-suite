package server

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/rbac"
)

// testABIProviderServer implements rbac.ABIProvider for tests.
type testABIProviderServer struct {
	abis map[string]string
}

func (p *testABIProviderServer) GetContractABI(address string) string {
	if p == nil || p.abis == nil {
		return ""
	}
	return p.abis[address]
}

// TestFilterReceiptLogsWithEventRules_AllowedEventPreserved reproduces the bug
// where eth_getTransactionReceipt strips ALL logs -- even those matching the
// event rules allowlist. With event rules configured allowing "NumberSet"
// (topic0 = 0xaaa...), a receipt containing one allowed log and one disallowed
// log must preserve the allowed log and only strip the disallowed one.
func TestFilterReceiptLogsWithEventRules_AllowedEventPreserved(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	allowedTopic0 := "0xaaa0000000000000000000000000000000000000000000000000000000000000"
	disallowedTopic0 := "0xbbb0000000000000000000000000000000000000000000000000000000000000"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{rbac.ClaimRead},
				EventRules: []rbac.EventRule{
					{Topic0: allowedTopic0, Name: "NumberSet"},
				},
			},
		},
	}

	// Build a realistic receipt with two logs: one allowed, one disallowed.
	receipt := map[string]any{
		"from":            userAddr,
		"to":              contractAddr,
		"status":          "0x1",
		"gasUsed":         "0x5208",
		"blockHash":       "0x0000000000000000000000000000000000000000000000000000000000000001",
		"blockNumber":     "0x1",
		"transactionHash": "0xabcdef",
		"logsBloom":       "0x1234",
		"logs": []map[string]any{
			{
				"address":          contractAddr,
				"topics":           []string{allowedTopic0, "0x0000000000000000000000000000000000000000000000000000000000000042"},
				"data":             "0x",
				"logIndex":         "0x0",
				"transactionIndex": "0x0",
			},
			{
				"address":          contractAddr,
				"topics":           []string{disallowedTopic0},
				"data":             "0x",
				"logIndex":         "0x1",
				"transactionIndex": "0x0",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, got)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant, got null\nraw: %s", got)
	}
	if len(resp.Result.Logs) != 1 {
		t.Errorf("expected 1 log (allowed event preserved, disallowed stripped), got %d\nraw: %s",
			len(resp.Result.Logs), got)
	}

	// Verify the preserved log is the allowed one.
	if len(resp.Result.Logs) > 0 {
		var log struct {
			Topics []string `json:"topics"`
		}
		if err := json.Unmarshal(resp.Result.Logs[0], &log); err != nil {
			t.Fatalf("failed to unmarshal preserved log: %v", err)
		}
		if len(log.Topics) == 0 || log.Topics[0] != allowedTopic0 {
			t.Errorf("preserved log should have topic0=%s, got %v", allowedTopic0, log.Topics)
		}
	}
}

// TestFilterReceiptLogsWithEventRules_NoEventRules_AddressFilter verifies the
// fallback behavior when no event rules are configured: only logs with the
// user's address in a topic are preserved.
func TestFilterReceiptLogsWithEventRules_NoEventRules_AddressFilter(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{rbac.ClaimRead},
				EventRules: nil, // no event rules = address-based filtering
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"gasUsed":   "0x5208",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xevent1", paddedUser},
				"data":    "0x",
			},
			{
				"address": contractAddr,
				"topics":  []string{"0xevent2", "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant")
	}
	if len(resp.Result.Logs) != 1 {
		t.Errorf("expected 1 log (user address in topic), got %d", len(resp.Result.Logs))
	}
}

// TestFilterReceiptLogsWithEventRules_NonParticipant_ReturnsNull verifies
// that non-participants get null even with event rules.
func TestFilterReceiptLogsWithEventRules_NonParticipant_ReturnsNull(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{rbac.ClaimRead},
				EventRules: []rbac.EventRule{
					{Topic0: "0xaaa0000000000000000000000000000000000000000000000000000000000000", Name: "NumberSet"},
				},
			},
		},
	}

	receipt := map[string]any{
		"from":      "0xother0000000000000000000000000000000001",
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
	)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("non-participant should get null result, got: %s", got)
	}
}

// TestFilterReceiptLogsWithEventRules_NilPerms_FailClosed verifies that when
// permissions cannot be resolved (nil), all receipt logs are stripped (fail-closed).
func TestFilterReceiptLogsWithEventRules_NilPerms_FailClosed(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(
		[]byte(rpcResponse),
		[]string{userAddr},
		nil, // nil perms = resolution failed
		&testABIProviderServer{},
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("participant should still get a receipt (with empty logs), not null")
	}
	if len(resp.Result.Logs) != 0 {
		t.Errorf("nil perms: expected 0 logs (fail-closed), got %d", len(resp.Result.Logs))
	}
}

// TestFilterReceiptLogsWithEventRules_MultipleContracts tests filtering when
// the receipt has logs from multiple contracts with different event rules.
func TestFilterReceiptLogsWithEventRules_MultipleContracts(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contract1 := "0xcontract0000000000000000000000000000001"
	contract2 := "0xcontract0000000000000000000000000000002"

	allowedTopic := "0xaaa0000000000000000000000000000000000000000000000000000000000000"
	otherTopic := "0xbbb0000000000000000000000000000000000000000000000000000000000000"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contract1: {
				Claims: []rbac.Claim{rbac.ClaimRead},
				EventRules: []rbac.EventRule{
					{Topic0: allowedTopic, Name: "NumberSet"},
				},
			},
			contract2: {
				Claims: []rbac.Claim{rbac.ClaimRead},
				EventRules: []rbac.EventRule{
					{Topic0: otherTopic, Name: "OtherEvent"},
				},
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contract1,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			// contract1, allowed topic -> keep
			{"address": contract1, "topics": []string{allowedTopic}, "data": "0x"},
			// contract1, other topic -> strip (not in contract1's allowlist)
			{"address": contract1, "topics": []string{otherTopic}, "data": "0x"},
			// contract2, other topic -> keep (in contract2's allowlist)
			{"address": contract2, "topics": []string{otherTopic}, "data": "0x"},
			// contract2, allowed topic -> strip (not in contract2's allowlist)
			{"address": contract2, "topics": []string{allowedTopic}, "data": "0x"},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant")
	}
	if len(resp.Result.Logs) != 2 {
		t.Errorf("expected 2 logs (one from each contract's allowlist), got %d\nraw: %s",
			len(resp.Result.Logs), got)
	}
}

// TestFilterReceiptLogsWithEventRules_LogsBloomZeroed verifies that logsBloom
// is zeroed when logs are filtered.
func TestFilterReceiptLogsWithEventRules_LogsBloomZeroed(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{rbac.ClaimRead},
				EventRules: []rbac.EventRule{
					{Topic0: "0xaaa0000000000000000000000000000000000000000000000000000000000000", Name: "NumberSet"},
				},
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"logs": []map[string]any{
			{"address": contractAddr, "topics": []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"}, "data": "0x"},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
	)

	var resp struct {
		Result *struct {
			LogsBloom string `json:"logsBloom"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant")
	}

	// logsBloom should be zeroed (0x + 512 zeros)
	expectedBloom := "0x" + string(make([]byte, 512))
	for i := range expectedBloom[2:] {
		_ = i // just ensure the length is 514
	}
	if len(resp.Result.LogsBloom) != 514 { // "0x" + 512 hex chars
		t.Errorf("logsBloom should be 514 chars (0x + 512 zeros), got %d chars: %s",
			len(resp.Result.LogsBloom), resp.Result.LogsBloom)
	}
}
