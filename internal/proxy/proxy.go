package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Proxy struct {
	targetURL string
	client    *http.Client
}

// DefaultTimeout is the default timeout for HTTP requests to the target node.
const DefaultTimeout = 30 * time.Second

func New(targetURL string) *Proxy {
	return &Proxy{
		targetURL: targetURL,
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Forward forwards a JSON-RPC request to the target node.
func (p *Proxy) Forward(reqBody []byte) ([]byte, int, error) {
	return p.ForwardWithAPIKey(reqBody, "", "")
}

// ForwardWithAPIKey forwards a JSON-RPC request with an optional API key
// for upstream RPC proxy authentication. If apiKey is non-empty, it is
// sent as a Bearer token in the Authorization header. If clientIP is
// non-empty, it is forwarded as an X-Forwarded-For header.
func (p *Proxy) ForwardWithAPIKey(reqBody []byte, apiKey string, clientIP string) ([]byte, int, error) {
	req, err := http.NewRequest("POST", p.targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed to forward request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed to read response: %w", err)
	}

	return body, resp.StatusCode, nil
}

// ErrBatchRequest is returned when a batch JSON-RPC request is detected.
// Batch requests are not supported for security reasons.
var ErrBatchRequest = fmt.Errorf("batch JSON-RPC requests are not supported")

// IsBatchRequest checks if the body contains a JSON-RPC batch request (array format).
func IsBatchRequest(body []byte) bool {
	// Trim whitespace and check if it starts with '['
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && trimmed[0] == '['
}

// ParseMethod extracts the method name from a JSON-RPC request
func ParseMethod(body []byte) (string, error) {
	// Check for batch request first
	if IsBatchRequest(body) {
		return "", ErrBatchRequest
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse JSON-RPC request: %w", err)
	}

	return req.Method, nil
}

// ParseRequest extracts method and params from a JSON-RPC request.
// Returns ErrBatchRequest if the request is a batch (array) request.
func ParseRequest(body []byte) (string, []interface{}, error) {
	// Check for batch request first
	if IsBatchRequest(body) {
		return "", nil, ErrBatchRequest
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil, fmt.Errorf("failed to parse JSON-RPC request: %w", err)
	}

	return req.Method, req.Params, nil
}

// HealthStatus contains the health check result for the target node
type HealthStatus struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// CheckHealth performs a health check on the target node by calling eth_blockNumber
func (p *Proxy) CheckHealth() HealthStatus {
	start := time.Now()

	// Create eth_blockNumber request
	reqBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_blockNumber",
		Params:  []interface{}{},
		ID:      1,
	})

	req, err := http.NewRequest("POST", p.targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return HealthStatus{
			Status: "error",
			URL:    p.targetURL,
			Error:  fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return HealthStatus{
			Status:    "disconnected",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     fmt.Sprintf("failed to connect: %v", err),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return HealthStatus{
			Status:    "error",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     fmt.Sprintf("failed to read response: %v", err),
		}
	}

	// Parse response to check for errors
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return HealthStatus{
			Status:    "error",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     fmt.Sprintf("invalid JSON-RPC response: %v", err),
		}
	}

	if rpcResp.Error != nil {
		return HealthStatus{
			Status:    "error",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     rpcResp.Error.Message,
		}
	}

	return HealthStatus{
		Status:    "connected",
		URL:       p.targetURL,
		LatencyMs: latency,
	}
}

// TargetURL returns the target URL for the proxy
func (p *Proxy) TargetURL() string {
	return p.targetURL
}
