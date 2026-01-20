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

func New(targetURL string) *Proxy {
	return &Proxy{
		targetURL: targetURL,
		client:    &http.Client{},
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

// Forward forwards a JSON-RPC request to the target node
func (p *Proxy) Forward(reqBody []byte) ([]byte, int, error) {
	// Create request to target node
	req, err := http.NewRequest("POST", p.targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
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

// ParseMethod extracts the method name from a JSON-RPC request
func ParseMethod(body []byte) (string, error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse JSON-RPC request: %w", err)
	}

	return req.Method, nil
}

// ParseRequest extracts method and params from a JSON-RPC request
func ParseRequest(body []byte) (string, []interface{}, error) {
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
