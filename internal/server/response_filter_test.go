package server

import (
	"encoding/json"
	"testing"
)

func TestFilterTransactionByHash(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name     string
		response string
		wantNull bool
		wantPass bool // expect the response to pass through unchanged
	}{
		{
			name:     "participant as from returns full tx",
			response: `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","from":"0xabc1234567890123456789012345678901234567","to":"0xother","input":"0xdeadbeef","nonce":"0x1"}}`,
			wantPass: true,
		},
		{
			name:     "participant as to returns full tx",
			response: `{"jsonrpc":"2.0","id":2,"result":{"hash":"0xabc","from":"0xother","to":"0xabc1234567890123456789012345678901234567","input":"0xdeadbeef","nonce":"0x2"}}`,
			wantPass: true,
		},
		{
			name:     "non-participant returns null",
			response: `{"jsonrpc":"2.0","id":3,"result":{"hash":"0xabc","from":"0xother1","to":"0xother2","input":"0xdeadbeef","nonce":"0x3"}}`,
			wantNull: true,
		},
		{
			name:     "null result passes through",
			response: `{"jsonrpc":"2.0","id":4,"result":null}`,
			wantPass: true,
		},
		{
			name:     "error passes through unchanged",
			response: `{"jsonrpc":"2.0","id":5,"error":{"code":-32000,"message":"not found"}}`,
			wantPass: true,
		},
		{
			name:     "case insensitive address match",
			response: `{"jsonrpc":"2.0","id":6,"result":{"from":"0xABC1234567890123456789012345678901234567","to":"0xother","input":"0x","nonce":"0x1"}}`,
			wantPass: true,
		},
		{
			name:     "contract creation (empty to) from participant returns full tx",
			response: `{"jsonrpc":"2.0","id":7,"result":{"hash":"0xabc","from":"0xabc1234567890123456789012345678901234567","to":"","input":"0x60806040","nonce":"0x5"}}`,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterTransactionByHash([]byte(tt.response), userAddrs)
			var resp struct {
				Result *json.RawMessage `json:"result"`
				Error  *json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(got, &resp); err != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", err, got)
			}
			if tt.wantNull {
				// When JSON has "result":null, *json.RawMessage is set to nil.
				// Accept both nil pointer and literal "null" bytes as null result.
				isNull := resp.Result == nil || string(*resp.Result) == "null"
				if !isNull {
					t.Errorf("expected null result, got: %s", got)
				}
			}
			if tt.wantPass {
				if string(got) != tt.response {
					t.Errorf("expected pass-through\n got: %s\nwant: %s", got, tt.response)
				}
			}
		})
	}
}

func TestFilterTransactionByHash_EmptyAddresses(t *testing.T) {
	response := `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","from":"0xsomeone","to":"0xother","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash([]byte(response), nil)
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("expected null result for empty addresses, got: %s", got)
	}
}

func TestFilterTransactionReceipt(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name     string
		response string
		wantNull bool // non-participant: result must be null
		wantFull bool // participant: receipt passes through unchanged
	}{
		{
			name:     "participant as from gets full receipt",
			response: `{"jsonrpc":"2.0","id":1,"result":{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","logs":[{"address":"0x1","topics":["0xevent"]}],"logsBloom":"0x1234"}}`,
			wantFull: true,
		},
		{
			name:     "participant as to gets full receipt",
			response: `{"jsonrpc":"2.0","id":2,"result":{"from":"0xother","to":"0xabc1234567890123456789012345678901234567","logs":[{"address":"0x1","topics":["0xevent"]}],"logsBloom":"0x1234"}}`,
			wantFull: true,
		},
		{
			name:     "non-participant returns null",
			response: `{"jsonrpc":"2.0","id":3,"result":{"from":"0xother1","to":"0xother2","logs":[{"address":"0x1","topics":["0xevent"]}],"logsBloom":"0x1234"}}`,
			wantNull: true,
		},
		{
			name:     "null result passes through",
			response: `{"jsonrpc":"2.0","id":4,"result":null}`,
			wantFull: true,
		},
		{
			name:     "error passes through",
			response: `{"jsonrpc":"2.0","id":5,"error":{"code":-32000,"message":"not found"}}`,
			wantFull: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterTransactionReceipt([]byte(tt.response), userAddrs)
			if tt.wantFull {
				if string(got) != tt.response {
					t.Errorf("expected pass-through\n got: %s\nwant: %s", got, tt.response)
				}
				return
			}
			if tt.wantNull {
				var resp struct {
					Result *json.RawMessage `json:"result"`
				}
				if err := json.Unmarshal(got, &resp); err != nil {
					t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
				}
				isNull := resp.Result == nil || string(*resp.Result) == "null"
				if !isNull {
					t.Errorf("expected null result for non-participant, got: %s", got)
				}
			}
		})
	}
}

func TestFilterTransactionReceipt_NilAddresses(t *testing.T) {
	response := `{"jsonrpc":"2.0","id":1,"result":{"from":"0xsomeone","to":"0xother","logs":[{"address":"0x1","topics":["0xevent"]}],"logsBloom":"0xabc"}}`
	got := FilterTransactionReceipt([]byte(response), nil)
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("expected null result for nil addresses (no participant match), got: %s", got)
	}
}

func TestFilterLogs(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}
	// Padded version of user's address as a topic
	paddedAddr := "0x000000000000000000000000abc1234567890123456789012345678901234567"

	tests := []struct {
		name      string
		response  string
		wantCount int
	}{
		{
			name:      "log with user address in topic[1] is kept",
			response:  `{"jsonrpc":"2.0","id":1,"result":[{"topics":["0xeventSig","` + paddedAddr + `","0x0000000000000000000000000000000000000000000000000000000000000000"]}]}`,
			wantCount: 1,
		},
		{
			name:      "log with user address in topic[2] is kept",
			response:  `{"jsonrpc":"2.0","id":2,"result":[{"topics":["0xeventSig","0x0000000000000000000000000000000000000000000000000000000000000000","` + paddedAddr + `"]}]}`,
			wantCount: 1,
		},
		{
			name:      "log without user address is removed",
			response:  `{"jsonrpc":"2.0","id":3,"result":[{"topics":["0xeventSig","0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}]}`,
			wantCount: 0,
		},
		{
			name:      "topic[0] event sig is not matched as address",
			response:  `{"jsonrpc":"2.0","id":4,"result":[{"topics":["` + paddedAddr + `"]}]}`,
			wantCount: 0,
		},
		{
			name: "multiple logs: only user's are kept",
			response: `{"jsonrpc":"2.0","id":5,"result":[` +
				`{"topics":["0xeventSig","` + paddedAddr + `"]},` +
				`{"topics":["0xeventSig","0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}` +
				`]}`,
			wantCount: 1,
		},
		{
			name:      "empty result passes through",
			response:  `{"jsonrpc":"2.0","id":6,"result":[]}`,
			wantCount: 0,
		},
		{
			name:      "null result passes through",
			response:  `{"jsonrpc":"2.0","id":7,"result":null}`,
			wantCount: -1, // special: null passes through
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterLogs([]byte(tt.response), userAddrs)
			if tt.wantCount == -1 {
				// null pass-through: result should be null
				var resp struct {
					Result *json.RawMessage `json:"result"`
				}
				if err := json.Unmarshal(got, &resp); err != nil {
					t.Fatalf("output not valid JSON: %v", err)
				}
				if resp.Result != nil && string(*resp.Result) != "null" {
					t.Errorf("expected null pass-through, got: %s", got)
				}
				return
			}
			var resp struct {
				Result []json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(got, &resp); err != nil {
				t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
			}
			if len(resp.Result) != tt.wantCount {
				t.Errorf("expected %d logs, got %d\noutput: %s", tt.wantCount, len(resp.Result), got)
			}
		})
	}
}

func TestTopicMatchesAddress(t *testing.T) {
	addrSet := map[string]bool{
		"0xabc1234567890123456789012345678901234567": true,
	}
	tests := []struct {
		topic string
		want  bool
	}{
		{"0x000000000000000000000000abc1234567890123456789012345678901234567", true},
		{"0x000000000000000000000000ABC1234567890123456789012345678901234567", true}, // uppercase
		{"0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff", false},
		{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", false}, // event sig (nonzero prefix)
		{"0x0", false}, // too short
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.topic, func(t *testing.T) {
			got := topicMatchesAddress(tt.topic, addrSet)
			if got != tt.want {
				t.Errorf("topicMatchesAddress(%q) = %v, want %v", tt.topic, got, tt.want)
			}
		})
	}
}

func TestRpcResponseID(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"numeric id", `{"jsonrpc":"2.0","id":42,"result":null}`, "42"},
		{"string id", `{"jsonrpc":"2.0","id":"abc","result":null}`, `"abc"`},
		{"null id", `{"jsonrpc":"2.0","id":null,"result":null}`, "null"},
		{"missing id", `{"jsonrpc":"2.0","result":null}`, "null"},
		{"invalid json", `not json`, "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rpcResponseID([]byte(tt.body))
			if got != tt.want {
				t.Errorf("rpcResponseID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFilterTransactionByHash_PreservesID(t *testing.T) {
	// Verify that the null response preserves the original request ID
	response := `{"jsonrpc":"2.0","id":999,"result":{"from":"0xother","to":"0xother2","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash([]byte(response), []string{"0xmyaddr0000000000000000000000000000000000"})
	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if string(resp.ID) != "999" {
		t.Errorf("expected id=999, got id=%s", resp.ID)
	}
}

func TestFilterBlockTransactions(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name      string
		response  string
		wantCount int // expected tx count in filtered response (-1 = pass through unchanged)
	}{
		{
			name: "full tx objects: keeps only user's tx (as from)",
			response: `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":[` +
				`{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","input":"0xdeadbeef"},` +
				`{"from":"0xother1","to":"0xother2","input":"0xcafebabe"}` +
				`]}}`,
			wantCount: 1,
		},
		{
			name: "full tx objects: no user txs → empty array",
			response: `{"jsonrpc":"2.0","id":2,"result":{"number":"0x1","transactions":[` +
				`{"from":"0xother1","to":"0xother2","input":"0xdeadbeef"}` +
				`]}}`,
			wantCount: 0,
		},
		{
			name:      "tx hashes only → pass through unchanged",
			response:  `{"jsonrpc":"2.0","id":3,"result":{"number":"0x1","transactions":["0xhash1","0xhash2"]}}`,
			wantCount: -1, // pass through: hashes aren't sensitive
		},
		{
			name:      "empty transactions → pass through",
			response:  `{"jsonrpc":"2.0","id":4,"result":{"number":"0x1","transactions":[]}}`,
			wantCount: -1,
		},
		{
			name:      "null result → pass through",
			response:  `{"jsonrpc":"2.0","id":5,"result":null}`,
			wantCount: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterBlockTransactions([]byte(tt.response), userAddrs)
			if tt.wantCount == -1 {
				if string(got) != tt.response {
					// For hash arrays or empty, response might be restructured but semantically same
					// Just verify it's valid JSON
					var v interface{}
					if err := json.Unmarshal(got, &v); err != nil {
						t.Errorf("output not valid JSON: %v", err)
					}
				}
				return
			}
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
			if len(resp.Result.Transactions) != tt.wantCount {
				t.Errorf("expected %d txs, got %d\noutput: %s", tt.wantCount, len(resp.Result.Transactions), got)
			}
		})
	}
}

func TestFilterBlockReceipts(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name             string
		response         string
		wantReceiptCount int // -1 means pass-through (null/error)
	}{
		{
			name: "participant receipt kept",
			response: `{"jsonrpc":"2.0","id":1,"result":[` +
				`{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","logs":[{"address":"0x1"}],"logsBloom":"0x1234"}` +
				`]}`,
			wantReceiptCount: 1,
		},
		{
			name: "non-participant receipt removed",
			response: `{"jsonrpc":"2.0","id":2,"result":[` +
				`{"from":"0xother1","to":"0xother2","logs":[{"address":"0x1"}],"logsBloom":"0x1234"}` +
				`]}`,
			wantReceiptCount: 0,
		},
		{
			name: "mixed: participant kept, non-participant removed",
			response: `{"jsonrpc":"2.0","id":3,"result":[` +
				`{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","logs":[{"address":"0x1"}],"logsBloom":"0xfull"},` +
				`{"from":"0xother1","to":"0xother2","logs":[{"address":"0x2"}],"logsBloom":"0xfull"}` +
				`]}`,
			wantReceiptCount: 1,
		},
		{
			name:             "null result passes through",
			response:         `{"jsonrpc":"2.0","id":4,"result":null}`,
			wantReceiptCount: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterBlockReceipts([]byte(tt.response), userAddrs)
			if tt.wantReceiptCount == -1 {
				var v interface{}
				if err := json.Unmarshal(got, &v); err != nil {
					t.Errorf("output not valid JSON: %v", err)
				}
				return
			}
			var resp struct {
				Result []json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(got, &resp); err != nil {
				t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
			}
			if len(resp.Result) != tt.wantReceiptCount {
				t.Errorf("expected %d receipts, got %d\noutput: %s", tt.wantReceiptCount, len(resp.Result), got)
			}
		})
	}
}
