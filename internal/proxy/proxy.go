package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
