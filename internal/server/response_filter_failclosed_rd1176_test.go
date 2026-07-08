package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"
)

// RD-1176 #6 — block response filters must fail CLOSED on a linked-address
// lookup error, not serve the full unfiltered block.
//
// Before the fix, applyResponseFilter's eth_getBlockByHash / eth_getBlockByNumber
// / eth_getBlockReceipts branches did `return responseBody` when
// GetLinkedEthAddresses errored, leaking every participant's transactions and
// receipts in the block to any authenticated caller during a transient DB
// error. The sibling handlers (getLogs, blockTxCount, txByHash) already failed
// closed. The fix passes nil addrs to FilterBlockTransactions / FilterBlockReceipts
// so the response is filtered to the empty set (a nil set matches nothing).
//
// Two layers of coverage:
//   - the primitive: FilterBlock{Transactions,Receipts}(body, nil, ...) drops
//     every tx/receipt while preserving block metadata (fail-closed);
//   - the branch: applyResponseFilter drives that primitive when the store's
//     GetLinkedEthAddresses returns an error.

// errLinkedAddrStore embeds the rbac.Store interface (nil) and overrides only
// GetLinkedEthAddresses to error. The block branches of applyResponseFilter
// touch no other store method, so the nil embed is never dereferenced on this
// path. Any accidental future call to another method panics loudly rather than
// silently passing — which is the behaviour we want from a test double.
type errLinkedAddrStore struct {
	rbac.Store
}

func (errLinkedAddrStore) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) {
	return nil, errors.New("simulated linked-address DB error")
}

func newProcessorWithErringStore() *JSONRPCProcessor {
	ctrl := rbac.NewAccessController(errLinkedAddrStore{}, time.Minute)
	return &JSONRPCProcessor{rbacAccessCtrl: ctrl}
}

// fullBlockResponse is a block with two txs (full objects) for a viewer who is
// party to NEITHER. logsBloom / gasUsed are set to non-zero to confirm the
// unconditional sanitisation still runs on the fail-closed path.
func fullBlockResponse() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"result":{` +
		`"number":"0x10","hash":"0xblock","logsBloom":"0xdead","gasUsed":"0x5208",` +
		`"transactions":[` +
		`{"hash":"0xtx1","from":"0xother1","to":"0xother2","input":"0x"},` +
		`{"hash":"0xtx2","from":"0xother3","to":"0xother4","input":"0x"}` +
		`]}}`)
}

func TestApplyResponseFilter_BlockByNumber_FailsClosedOnDBError_RD1176(t *testing.T) {
	p := newProcessorWithErringStore()
	req := &ProcessRequest{
		Method: "eth_getBlockByNumber",
		UserID: "did:viewer",
		Params: []any{"0x10", true}, // full-tx-objects request
	}

	got := p.applyResponseFilter(context.Background(), req, nil, fullBlockResponse())

	var resp struct {
		Result *struct {
			Number       string            `json:"number"`
			LogsBloom    string            `json:"logsBloom"`
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
	}
	if resp.Result == nil {
		t.Fatal("block result must not be null on the fail-closed path")
	}
	if len(resp.Result.Transactions) != 0 {
		t.Fatalf("RD-1176 regression: DB error must fail CLOSED (empty tx array), "+
			"got %d txs — the block was served UNFILTERED. Output: %s",
			len(resp.Result.Transactions), got)
	}
	if resp.Result.Number != "0x10" {
		t.Errorf("block metadata must be preserved, got number=%q", resp.Result.Number)
	}
	if !strings.HasPrefix(resp.Result.LogsBloom, "0x0") {
		t.Errorf("logsBloom must still be zeroed on the fail-closed path, got %q", resp.Result.LogsBloom)
	}
}

func TestApplyResponseFilter_BlockReceipts_FailsClosedOnDBError_RD1176(t *testing.T) {
	p := newProcessorWithErringStore()
	req := &ProcessRequest{
		Method: "eth_getBlockReceipts",
		UserID: "did:viewer",
		Params: []any{"0x10"},
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":[` +
		`{"from":"0xother1","to":"0xother2","status":"0x1","gasUsed":"0x5208","logs":[]},` +
		`{"from":"0xother3","to":"0xother4","status":"0x1","gasUsed":"0x5208","logs":[]}` +
		`]}`)

	got := p.applyResponseFilter(context.Background(), req, nil, body)

	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
	}
	if len(resp.Result) != 0 {
		t.Fatalf("RD-1176 regression: DB error must fail CLOSED (empty receipts array), "+
			"got %d receipts — receipts were served UNFILTERED. Output: %s",
			len(resp.Result), got)
	}
}

// Primitive-level guards: nil addrs is the exact value the fix passes. These
// pin that a nil set matches nothing (fail-closed) so the branch fix above
// cannot be silently defeated by a change to the filter's nil handling.
func TestFilterBlockTransactions_NilAddrs_FailsClosed_RD1176(t *testing.T) {
	got := FilterBlockTransactions(fullBlockResponse(), nil, true)
	var resp struct {
		Result *struct {
			Transactions []json.RawMessage `json:"transactions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil || len(resp.Result.Transactions) != 0 {
		t.Fatalf("nil addrs must match nothing (fail-closed), got: %s", got)
	}
}

func TestFilterBlockReceipts_NilAddrs_FailsClosed_RD1176(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":[{"from":"0xa","to":"0xb","status":"0x1","logs":[]}]}`)
	got := FilterBlockReceipts(body, nil)
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(resp.Result) != 0 {
		t.Fatalf("nil addrs must drop every receipt (fail-closed), got: %s", got)
	}
}

// RD-1176 #8 — the block-transaction-count badge routes its filtered-count
// error through visibleCountOrZero, which must fail SAFE to 0, never fall
// through to the raw chain-wide total. Pins the primitive the two
// getExplorerBlock* handlers now rely on.
//
// #7's sibling primitive (RedactionEngine.RedactAddress returns "[REDACTED]"
// on a GetBatchVisibility error) is pinned by TestRedactAddress_DBError in the
// explorer package; the contract-creator handler now assigns that value
// unconditionally instead of discarding it on error.
func TestVisibleCountOrZero_FailsSafeToZero_RD1176(t *testing.T) {
	if got := visibleCountOrZero(999, errors.New("count query failed"), "block_transactions", "0xblock"); got != 0 {
		t.Fatalf("count error must fail safe to 0 (never the raw total), got %d", got)
	}
	if got := visibleCountOrZero(7, nil, "block_transactions", "0xblock"); got != 7 {
		t.Fatalf("no error must return the computed count, got %d", got)
	}
}
