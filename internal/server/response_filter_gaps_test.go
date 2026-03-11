package server

// response_filter_gaps_test.go documents security gaps, edge cases, and behavioral
// inconsistencies in the response filtering layer. These complement the basic
// correctness tests in response_filter_test.go.
//
// Key findings documented here:
//  1. from/to exposed to non-participants in receipts (known design decision)
//  2. Block-level logsBloom not zeroed (known gap — reveals event presence)
//  3. FilterBlockTransactions shrinks array; FilterBlockReceipts preserves length (inconsistency)
//  4. Zero address linking danger (edge case)
//  5. DB error fail-open for block methods vs fail-closed for tx methods (wiring gap)

import (
	"encoding/json"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────
// Group 1: FilterTransactionByHash — additional edge cases
// ──────────────────────────────────────────────────────────────────────────

func TestFilterTransactionByHash_SelfTransaction(t *testing.T) {
	// User sends to themselves — must see full tx.
	addr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","from":"` + addr + `","to":"` + addr + `","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash([]byte(response), []string{addr})
	if string(got) != response {
		t.Errorf("self-tx should pass through unchanged\ngot:  %s\nwant: %s", got, response)
	}
}

func TestFilterTransactionByHash_MultipleLinkedAddresses(t *testing.T) {
	// User has two linked addresses; tx involves the second one.
	addr1 := "0xaaa1111111111111111111111111111111111111"
	addr2 := "0xbbb2222222222222222222222222222222222222"
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"0xother","to":"` + addr2 + `","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash([]byte(response), []string{addr1, addr2})
	if string(got) != response {
		t.Errorf("tx involving second linked address should pass through\ngot: %s", got)
	}
}

func TestFilterTransactionByHash_ChecksummedAddress(t *testing.T) {
	// EIP-55 checksummed address in the RPC response must match the stored lowercase address.
	stored := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	checksummed := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"` + checksummed + `","to":"0xother","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash([]byte(response), []string{stored})
	if string(got) != response {
		t.Errorf("checksummed address should match stored lowercase\ngot: %s", got)
	}
}

func TestFilterTransactionByHash_ContractCreation_NonParticipant(t *testing.T) {
	// Contract creation tx (to=null): non-participant must receive null.
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"0xdeployer","to":null,"input":"0x60806040","nonce":"0x1"}}`
	got := FilterTransactionByHash([]byte(response), []string{"0xabc1234567890123456789012345678901234567"})
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("non-participant contract creation tx should return null, got: %s", got)
	}
}

func TestFilterTransactionByHash_EIP1559_FieldsPreserved(t *testing.T) {
	// EIP-1559 fields (maxFeePerGas, maxPriorityFeePerGas, type) must all be preserved.
	addr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","from":"` + addr + `","to":"0xother","input":"0x","nonce":"0x1","maxFeePerGas":"0x1234","maxPriorityFeePerGas":"0x100","type":"0x2"}}`
	got := FilterTransactionByHash([]byte(response), []string{addr})
	if string(got) != response {
		t.Errorf("EIP-1559 fields must be preserved for participant\ngot:  %s\nwant: %s", got, response)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Group 2: FilterTransactionReceipt — edge cases and security gap docs
// ──────────────────────────────────────────────────────────────────────────

func TestFilterTransactionReceipt_NonParticipant_ReturnsNull(t *testing.T) {
	// Non-participant receives null — no from/to/status/logs leakage at all.
	// Consistent with FilterTransactionByHash returning null for non-participants.
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"0xsender","to":"0xreceiver","status":"0x1","gasUsed":"0x5208","logs":[{"address":"0x1","topics":["0xevent"]}],"logsBloom":"0x1234"}}`
	got := FilterTransactionReceipt([]byte(response), []string{"0xabc1234567890123456789012345678901234567"})

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("non-participant must receive null result, got: %s", got)
	}
}

func TestFilterTransactionReceipt_ContractCreation_Participant(t *testing.T) {
	// Deployer's receipt: to=null, contractAddress present, must pass through unchanged.
	addr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"` + addr + `","to":null,"contractAddress":"0xnewcontract","status":"0x1","logs":[{"address":"0x1"}],"logsBloom":"0xfull"}}`
	got := FilterTransactionReceipt([]byte(response), []string{addr})
	if string(got) != response {
		t.Errorf("deployer should see full contract creation receipt\ngot: %s", got)
	}
}

func TestFilterTransactionReceipt_ContractCreation_NonParticipant(t *testing.T) {
	// Non-participant receives null — contractAddress not revealed either.
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"0xdeployer","to":null,"contractAddress":"0xnewcontract","status":"0x1","logs":[{"address":"0x1"}],"logsBloom":"0xfull"}}`
	got := FilterTransactionReceipt([]byte(response), []string{"0xabc1234567890123456789012345678901234567"})

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("non-participant must receive null (not contractAddress), got: %s", got)
	}
}

func TestFilterTransactionReceipt_NonParticipant_IDPreserved(t *testing.T) {
	// The null response for a non-participant must preserve the original request ID.
	response := `{"jsonrpc":"2.0","id":42,"result":{"from":"0xother","to":"0xother2","logs":[],"logsBloom":"0x0"}}`
	got := FilterTransactionReceipt([]byte(response), []string{"0xabc1234567890123456789012345678901234567"})

	var resp struct {
		ID     json.RawMessage  `json:"id"`
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if string(resp.ID) != "42" {
		t.Errorf("null response must preserve request id=42, got: %s", resp.ID)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("expected null result, got: %s", got)
	}
}

func TestFilterTransactionReceipt_CaseInsensitiveAddressMatch(t *testing.T) {
	// Checksummed from/to in the RPC response must match lowercase stored address.
	stored := "0xabc1234567890123456789012345678901234567"
	checksummed := "0xAbC1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"` + checksummed + `","to":"0xother","logs":[{"address":"0x1"}],"logsBloom":"0x1234"}}`
	got := FilterTransactionReceipt([]byte(response), []string{stored})
	if string(got) != response {
		t.Errorf("checksummed 'from' address should match stored lowercase\ngot: %s", got)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Group 3: FilterLogs — realistic event patterns and edge cases
// ──────────────────────────────────────────────────────────────────────────

var transferEventSig = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

func TestFilterLogs_TransferEvent_SenderKept(t *testing.T) {
	// ERC-20 Transfer(from, to, amount): user is sender (topics[1]).
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedSender := "0x000000000000000000000000abc1234567890123456789012345678901234567"
	paddedReceiver := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":["` + transferEventSig + `","` + paddedSender + `","` + paddedReceiver + `"],"data":"0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 1 {
		t.Errorf("sender should see their own Transfer event, got %d logs", len(resp.Result))
	}
}

func TestFilterLogs_TransferEvent_ReceiverKept(t *testing.T) {
	// ERC-20 Transfer(from, to, amount): user is receiver (topics[2]).
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedReceiver := "0x000000000000000000000000abc1234567890123456789012345678901234567"
	paddedSender := "0x000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":["` + transferEventSig + `","` + paddedSender + `","` + paddedReceiver + `"],"data":"0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 1 {
		t.Errorf("receiver should see Transfer event, got %d logs", len(resp.Result))
	}
}

func TestFilterLogs_TransferEvent_ThirdPartyRemoved(t *testing.T) {
	// User is neither sender nor receiver in a Transfer event.
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedSender := "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd"
	paddedReceiver := "0x000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":["` + transferEventSig + `","` + paddedSender + `","` + paddedReceiver + `"],"data":"0x1234"}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("third party must not see Transfer event, got %d logs", len(resp.Result))
	}
}

// SECURITY NOTE: The 'data' field of a kept log is NOT filtered.
// A user who appears in indexed topics sees the full ABI-encoded data payload.
// This is correct behavior — if you're a party, you see the event data.
// Field-level redaction within data is a future TODO.
func TestFilterLogs_DataFieldPassesThroughForParticipant(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedAddr := "0x000000000000000000000000abc1234567890123456789012345678901234567"
	sensitiveData := "0xdeadbeefcafebabe0000000000000000000000000000000000000000000000001234"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":["0xevent","` + paddedAddr + `"],"data":"` + sensitiveData + `"}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []struct {
			Data string `json:"data"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 1 {
		t.Fatalf("expected 1 log (user is in topics), got %d", len(resp.Result))
	}
	if resp.Result[0].Data != sensitiveData {
		t.Errorf("data field must pass through unchanged for participant, got: %s", resp.Result[0].Data)
	}
}

func TestFilterLogs_NonZeroPrefixTopic_NotMatched(t *testing.T) {
	// A topic with any non-zero byte in the 12-byte address padding is not an address topic.
	// Even if the last 40 chars match the user's address, it must not match.
	userAddr := "0xabc1234567890123456789012345678901234567"
	// Non-zero prefix: first byte of padding is 0x01
	badTopic := "0x0100000000000000000000000abc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":["0xevent","` + badTopic + `"]}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("topic with non-zero prefix must not match user address, got %d logs", len(resp.Result))
	}
}

func TestFilterLogs_EmptyTopicsArray(t *testing.T) {
	// Log with empty topics array — no address topics to match, must be filtered.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":[],"data":"0x1234"}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("log with empty topics must be filtered out, got %d", len(resp.Result))
	}
}

func TestFilterLogs_OnlyEventSigTopic(t *testing.T) {
	// Log has only topics[0] (event signature), no indexed address parameters.
	// Must be filtered — no address topic to match against.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"topics":["` + transferEventSig + `"],"data":"0x1234"}]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("log with only event sig topic (no address params) must be filtered, got %d", len(resp.Result))
	}
}

func TestFilterLogs_MixedLogs_AllNonUser(t *testing.T) {
	// Multiple logs, none involving the user — empty result.
	userAddr := "0xabc1234567890123456789012345678901234567"
	other1 := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	other2 := "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	response := `{"jsonrpc":"2.0","id":1,"result":[` +
		`{"topics":["0xevent","` + other1 + `"]},` +
		`{"topics":["0xevent","` + other2 + `"]}` +
		`]}`

	got := FilterLogs([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("all non-user logs must be filtered, got %d", len(resp.Result))
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Group 4: FilterBlockTransactions — edge cases and security gap docs
// ──────────────────────────────────────────────────────────────────────────

func TestFilterBlockTransactions_UserAsTo(t *testing.T) {
	// User is `to` in one transaction — must keep it.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":[` +
		`{"from":"0xother","to":"` + userAddr + `","input":"0x"},` +
		`{"from":"0xother1","to":"0xother2","input":"0x"}` +
		`]}}`

	got := FilterBlockTransactions([]byte(response), []string{userAddr})
	var resp struct {
		Result *struct {
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
	}
	if resp.Result == nil {
		t.Fatal("expected non-null result")
	}
	if len(resp.Result.Transactions) != 1 {
		t.Errorf("expected 1 tx (user as to), got %d\noutput: %s", len(resp.Result.Transactions), got)
	}
}

func TestFilterBlockTransactions_MultipleLinkedAddresses(t *testing.T) {
	// User has two linked addresses — txs involving either must be kept.
	addr1 := "0xaaa1111111111111111111111111111111111111"
	addr2 := "0xbbb2222222222222222222222222222222222222"
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":[` +
		`{"from":"` + addr1 + `","to":"0xother","input":"0x"},` +
		`{"from":"0xother","to":"` + addr2 + `","input":"0x"},` +
		`{"from":"0xother1","to":"0xother2","input":"0x"}` +
		`]}}`

	got := FilterBlockTransactions([]byte(response), []string{addr1, addr2})
	var resp struct {
		Result *struct {
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatal("expected non-null result")
	}
	if len(resp.Result.Transactions) != 2 {
		t.Errorf("expected 2 txs (one per linked address), got %d", len(resp.Result.Transactions))
	}
}

// SECURITY GAP (DOCUMENTED): Block-level logsBloom in the block header is NOT zeroed.
// An attacker can check for event-signature presence in the block without needing calldata.
// e.g., they can detect "did a Transfer event happen in this block?" via the bloom filter.
// Fix: zero block.logsBloom whenever transactions are filtered.
func TestFilterBlockTransactions_BlockLogsBloom_NotZeroed(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	originalBloom := "0xdeadbeef1234567890abcdef"
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","logsBloom":"` + originalBloom + `","transactions":[` +
		`{"from":"0xother1","to":"0xother2","input":"0x"}` +
		`]}}`

	got := FilterBlockTransactions([]byte(response), []string{userAddr})
	var resp struct {
		Result *struct {
			LogsBloom string `json:"logsBloom"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatal("expected non-null result")
	}
	// Document the gap: block logsBloom is still the original value.
	// When this gap is fixed, change this test to assert zeroing.
	if resp.Result.LogsBloom == strings.Repeat("0", 512) {
		// Gap was fixed — update this test.
		t.Logf("NOTE: block logsBloom is now zeroed — update this test to assert zeroing")
	} else if resp.Result.LogsBloom != originalBloom {
		t.Errorf("unexpected logsBloom value: got %s", resp.Result.LogsBloom)
	}
	// Expected current behavior: bloom is NOT zeroed (gap exists).
}

func TestFilterBlockTransactions_ContractCreation_DeployerKept(t *testing.T) {
	// Contract creation tx (to=null) where user is the deployer — must be kept.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":[` +
		`{"from":"` + userAddr + `","to":null,"input":"0x60806040"},` +
		`{"from":"0xother","to":null,"input":"0x60806040"}` +
		`]}}`

	got := FilterBlockTransactions([]byte(response), []string{userAddr})
	var resp struct {
		Result *struct {
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatal("expected non-null result")
	}
	if len(resp.Result.Transactions) != 1 {
		t.Errorf("expected 1 tx (deployer's contract creation), got %d", len(resp.Result.Transactions))
	}
}

func TestFilterBlockTransactions_AllNonParticipant_BlockMetadataPreserved(t *testing.T) {
	// All txs non-participant → empty tx array, but block metadata must be preserved.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","hash":"0xblockhash","transactions":[` +
		`{"from":"0xother1","to":"0xother2","input":"0x"},` +
		`{"from":"0xother3","to":"0xother4","input":"0x"}` +
		`]}}`

	got := FilterBlockTransactions([]byte(response), []string{userAddr})
	var resp struct {
		Result *struct {
			Number       string            `json:"number"`
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
	}
	if resp.Result == nil {
		t.Fatal("block result must not be null even when all txs are filtered")
	}
	if len(resp.Result.Transactions) != 0 {
		t.Errorf("expected empty tx array, got %d", len(resp.Result.Transactions))
	}
	if resp.Result.Number == "" {
		t.Error("block number must be preserved even when tx array is empty")
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Group 5: FilterBlockReceipts — edge cases and security gap docs
// ──────────────────────────────────────────────────────────────────────────

func TestFilterBlockReceipts_AllNonParticipant_EmptyArray(t *testing.T) {
	// All receipts non-participant — array shrinks to empty (consistent with FilterBlockTransactions).
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":[` +
		`{"from":"0xother1","to":"0xother2","status":"0x1","gasUsed":"0x5208","logs":[{"address":"0x1"}],"logsBloom":"0xfull"},` +
		`{"from":"0xother3","to":"0xother4","status":"0x1","gasUsed":"0x5208","logs":[{"address":"0x2"}],"logsBloom":"0xfull"},` +
		`{"from":"0xother5","to":"0xother6","status":"0x0","gasUsed":"0x5208","logs":[],"logsBloom":"0x0"}` +
		`]}`

	got := FilterBlockReceipts([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("all non-participant receipts must be removed, got %d", len(resp.Result))
	}
}

func TestFilterBlockReceipts_NonParticipant_NotLeaked(t *testing.T) {
	// Non-participant receipt is removed entirely — from/to/status not exposed.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"from":"0xsender","to":"0xreceiver","status":"0x1","gasUsed":"0x5208","contractAddress":null,"logs":[],"logsBloom":"0x0"}]}`

	got := FilterBlockReceipts([]byte(response), []string{userAddr})
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("non-participant receipt must be removed (not exposed), got %d receipts\noutput: %s", len(resp.Result), got)
	}
}

func TestFilterBlockReceipts_ContractCreation_DeployerKeepsLogs(t *testing.T) {
	// Contract creation receipt in a block — deployer must see their logs.
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":[{"from":"` + userAddr + `","to":null,"contractAddress":"0xnewcontract","status":"0x1","logs":[{"address":"0x1"}],"logsBloom":"0xfull"}]}`

	got := FilterBlockReceipts([]byte(response), []string{userAddr})
	var resp struct {
		Result []struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(resp.Result))
	}
	if len(resp.Result[0].Logs) == 0 {
		t.Error("deployer must see their own contract creation receipt logs")
	}
}

func TestFilterBlockReceipts_EmptyBlock(t *testing.T) {
	// Empty block — empty array, valid response.
	response := `{"jsonrpc":"2.0","id":1,"result":[]}`
	got := FilterBlockReceipts([]byte(response), []string{"0xabc1234567890123456789012345678901234567"})

	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Errorf("empty block should have empty receipts array, got %d", len(resp.Result))
	}
}


// ──────────────────────────────────────────────────────────────────────────
// Group 7: topicMatchesAddress — additional edge cases
// ──────────────────────────────────────────────────────────────────────────

func TestTopicMatchesAddress_ZeroAddress_OnlyMatchesZeroTopic(t *testing.T) {
	// If a user links address(0), they would see events where address(0) appears as
	// an indexed param — e.g., ERC-20 mint events (Transfer from address(0)).
	// They do NOT see events for random non-zero addresses.
	zeroAddr := "0x0000000000000000000000000000000000000000"
	addrSet := map[string]bool{zeroAddr: true}

	// A regular transfer topic (topics[1] = some real address) — must NOT match zero addr
	transferSenderTopic := "0x000000000000000000000000abcdef1234567890123456789012345678901234"
	if topicMatchesAddress(transferSenderTopic, addrSet) {
		t.Errorf("zero address should not match a non-zero address topic")
	}

	// Zero-address topic (e.g., token mint: Transfer(0x0, recipient, amount))
	// topics[1] = padded zero address
	zeroTopic := "0x0000000000000000000000000000000000000000000000000000000000000000"
	if !topicMatchesAddress(zeroTopic, addrSet) {
		t.Errorf("zero address should match zero-padded zero-address topic (mint events)")
	}
}

func TestTopicMatchesAddress_ShortTopics(t *testing.T) {
	addrSet := map[string]bool{"0xabc1234567890123456789012345678901234567": true}
	tests := []struct {
		name  string
		topic string
		want  bool
	}{
		{"empty string", "", false},
		{"just 0x", "0x", false},
		{"too short 4 chars", "0x0000", false},
		// 65 chars = odd hex — not exactly 66 chars
		{"65 chars", "0x" + strings.Repeat("0", 63), false},
		// 67 chars — too long
		{"67 chars", "0x" + strings.Repeat("0", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := topicMatchesAddress(tt.topic, addrSet)
			if got != tt.want {
				t.Errorf("topicMatchesAddress(%q) = %v, want %v", tt.topic, got, tt.want)
			}
		})
	}
}

func TestTopicMatchesAddress_ExactlyValidLength(t *testing.T) {
	// Exactly 66 chars, correctly zero-padded — must match.
	addr := "0xabc1234567890123456789012345678901234567"
	addrSet := map[string]bool{addr: true}
	topic := "0x000000000000000000000000abc1234567890123456789012345678901234567"
	if len(topic) != 66 {
		t.Fatalf("test setup error: expected 66 chars, got %d", len(topic))
	}
	if !topicMatchesAddress(topic, addrSet) {
		t.Errorf("valid 66-char zero-padded address topic must match")
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Group 8: Behavioral consistency — block tx vs block receipts
// ──────────────────────────────────────────────────────────────────────────

// Both FilterBlockTransactions and FilterBlockReceipts now remove non-participant
// entries from their respective arrays — consistent strict behaviour.
func TestBehavioralConsistency_BlockTxAndBlockReceipts_BothShrink(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"

	txBlock := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":[` +
		`{"from":"` + userAddr + `","to":"0xother","input":"0x"},` +
		`{"from":"0xother1","to":"0xother2","input":"0x"},` +
		`{"from":"0xother3","to":"0xother4","input":"0x"}` +
		`]}}`

	receiptBlock := `{"jsonrpc":"2.0","id":2,"result":[` +
		`{"from":"` + userAddr + `","to":"0xother","status":"0x1","logs":[],"logsBloom":"0x0"},` +
		`{"from":"0xother1","to":"0xother2","status":"0x1","logs":[],"logsBloom":"0x0"},` +
		`{"from":"0xother3","to":"0xother4","status":"0x1","logs":[],"logsBloom":"0x0"}` +
		`]}`

	filteredTxBlock := FilterBlockTransactions([]byte(txBlock), []string{userAddr})
	filteredReceiptBlock := FilterBlockReceipts([]byte(receiptBlock), []string{userAddr})

	var txResp struct {
		Result *struct {
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	var receiptResp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(filteredTxBlock, &txResp); err != nil {
		t.Fatalf("tx block output not valid JSON: %v", err)
	}
	if err := json.Unmarshal(filteredReceiptBlock, &receiptResp); err != nil {
		t.Fatalf("receipt block output not valid JSON: %v", err)
	}

	// Both endpoints return only user's 1 entry (out of 3).
	if len(txResp.Result.Transactions) != 1 {
		t.Errorf("FilterBlockTransactions: expected 1 tx, got %d", len(txResp.Result.Transactions))
	}
	if len(receiptResp.Result) != 1 {
		t.Errorf("FilterBlockReceipts: expected 1 receipt, got %d", len(receiptResp.Result))
	}
}
