package tracer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout is the default timeout for trace calls.
const DefaultTimeout = 30 * time.Second

// TraceResult contains the parsed results of a debug_traceCall.
type TraceResult struct {
	CallTargets []CallTarget // All CALL/DELEGATECALL/STATICCALL targets
	HasCreate   bool         // Contains CREATE operations
	HasCreate2  bool         // Contains CREATE2 operations
	GasUsed     uint64
	Error       string
}

// CallTarget represents a single call operation in the trace.
type CallTarget struct {
	Type  string // "CALL", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"
	From  string
	To    string
	Depth int
}

// Tracer provides debug_traceCall functionality for an Ethereum node.
type Tracer struct {
	nodeURL string
	client  *http.Client
	timeout time.Duration
}

// NewTracer creates a new Tracer instance.
func NewTracer(nodeURL string, timeout time.Duration) *Tracer {
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Tracer{
		nodeURL: nodeURL,
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// jsonRPCRequest represents a JSON-RPC request.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

// jsonRPCResponse represents a JSON-RPC response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// rpcError represents a JSON-RPC error.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// callFrame represents a single frame in the call trace.
// This matches the output format of the "callTracer" preset.
type callFrame struct {
	Type    string      `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to,omitempty"`
	Value   string      `json:"value,omitempty"`
	Gas     string      `json:"gas,omitempty"`
	GasUsed string      `json:"gasUsed,omitempty"`
	Input   string      `json:"input,omitempty"`
	Output  string      `json:"output,omitempty"`
	Error   string      `json:"error,omitempty"`
	Calls   []callFrame `json:"calls,omitempty"`
}

// TraceCall performs a debug_traceCall on the upstream node and returns
// the parsed trace result with all call targets.
func (t *Tracer) TraceCall(ctx context.Context, from, to, data, value string, blockTag string) (*TraceResult, error) {
	// Build the call object
	callObj := map[string]string{}
	if from != "" {
		callObj["from"] = from
	}
	if to != "" {
		callObj["to"] = to
	}
	if data != "" {
		callObj["data"] = data
	}
	if value != "" {
		callObj["value"] = value
	}

	// Use the callTracer preset with onlyTopCall: false to get all nested calls
	tracerConfig := map[string]any{
		"tracer": "callTracer",
		"tracerConfig": map[string]any{
			"onlyTopCall": false,
		},
	}

	// Build the JSON-RPC request
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "debug_traceCall",
		Params:  []any{callObj, blockTag, tracerConfig},
		ID:      1,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request with context
	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON-RPC response
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Parse the call frame result
	var frame callFrame
	if err := json.Unmarshal(rpcResp.Result, &frame); err != nil {
		return nil, fmt.Errorf("failed to parse trace result: %w", err)
	}

	// Extract all call targets from the trace
	result := &TraceResult{
		CallTargets: make([]CallTarget, 0),
		Error:       frame.Error,
	}

	// Parse gas used from the top-level frame
	if frame.GasUsed != "" {
		result.GasUsed = parseHexUint64(frame.GasUsed)
	}

	// Recursively extract all call targets
	t.extractCallTargets(&frame, result, 0)

	return result, nil
}

// extractCallTargets recursively extracts all call targets from a call frame.
func (t *Tracer) extractCallTargets(frame *callFrame, result *TraceResult, depth int) {
	// Check the type and add to result
	switch frame.Type {
	case "CALL", "DELEGATECALL", "STATICCALL":
		result.CallTargets = append(result.CallTargets, CallTarget{
			Type:  frame.Type,
			From:  frame.From,
			To:    frame.To,
			Depth: depth,
		})
	case "CREATE":
		result.HasCreate = true
		result.CallTargets = append(result.CallTargets, CallTarget{
			Type:  frame.Type,
			From:  frame.From,
			To:    frame.To, // For CREATE, "to" is the created contract address
			Depth: depth,
		})
	case "CREATE2":
		result.HasCreate2 = true
		result.CallTargets = append(result.CallTargets, CallTarget{
			Type:  frame.Type,
			From:  frame.From,
			To:    frame.To, // For CREATE2, "to" is the created contract address
			Depth: depth,
		})
	}

	// Recursively process nested calls
	for i := range frame.Calls {
		t.extractCallTargets(&frame.Calls[i], result, depth+1)
	}
}

// TraceTransaction traces an already-mined transaction by hash using debug_traceTransaction.
// Used for post-mining verification of runtime CREATE/CREATE2 addresses.
func (t *Tracer) TraceTransaction(ctx context.Context, txHash string) (*TraceResult, error) {
	// Use the callTracer preset with onlyTopCall: false to get all nested calls
	tracerConfig := map[string]any{
		"tracer": "callTracer",
		"tracerConfig": map[string]any{
			"onlyTopCall": false,
		},
	}

	// Build the JSON-RPC request
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "debug_traceTransaction",
		Params:  []any{txHash, tracerConfig},
		ID:      1,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request with context
	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON-RPC response
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Parse the call frame result
	var frame callFrame
	if err := json.Unmarshal(rpcResp.Result, &frame); err != nil {
		return nil, fmt.Errorf("failed to parse trace result: %w", err)
	}

	// Extract all call targets from the trace
	result := &TraceResult{
		CallTargets: make([]CallTarget, 0),
		Error:       frame.Error,
	}

	// Parse gas used from the top-level frame
	if frame.GasUsed != "" {
		result.GasUsed = parseHexUint64(frame.GasUsed)
	}

	// Recursively extract all call targets
	t.extractCallTargets(&frame, result, 0)

	return result, nil
}

// HasCode checks if an address has contract code deployed.
// Returns true if the address is a contract (has non-empty code), false for EOAs.
func (t *Tracer) HasCode(ctx context.Context, address string) (bool, error) {
	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getCode",
		Params:  []any{address, "latest"},
		ID:      1,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.nodeURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("eth_getCode request failed: %w", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	if rpcResp.Error != nil {
		return false, fmt.Errorf("eth_getCode RPC error: %s", rpcResp.Error.Message)
	}

	// Parse the result - it's a hex string of the bytecode
	var code string
	if err := json.Unmarshal(rpcResp.Result, &code); err != nil {
		return false, fmt.Errorf("failed to parse code result: %w", err)
	}

	// EOAs return "0x", contracts return their bytecode
	code = strings.TrimSpace(code)
	return code != "" && code != "0x" && code != "0X", nil
}

// parseHexUint64 parses a hex string (with or without 0x prefix) to uint64.
func parseHexUint64(s string) uint64 {
	if len(s) == 0 {
		return 0
	}

	// Remove 0x prefix if present
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}

	var result uint64
	for _, c := range s {
		result *= 16
		switch {
		case c >= '0' && c <= '9':
			result += uint64(c - '0')
		case c >= 'a' && c <= 'f':
			result += uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result += uint64(c - 'A' + 10)
		}
	}
	return result
}
