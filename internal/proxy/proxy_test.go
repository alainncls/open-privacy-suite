package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseMethod(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{
			name:    "valid eth_call",
			body:    `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			want:    "eth_call",
			wantErr: false,
		},
		{
			name:    "valid eth_getBalance",
			body:    `{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x123", "latest"],"id":2}`,
			want:    "eth_getBalance",
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			body:    `{"jsonrpc":"2.0","method"`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "missing method",
			body:    `{"jsonrpc":"2.0","params":[],"id":1}`,
			want:    "",
			wantErr: false, // Method will be empty string, not an error
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := ParseMethod([]byte(tt.body))
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if method != tt.want {
				t.Errorf("got method %q, want %q", method, tt.want)
			}
		})
	}
}

func TestForward(t *testing.T) {
	// Create a mock server
	mockResponse := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  "0x123",
		ID:      1,
	}
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()
	
	proxy := New(server.URL)
	
	requestBody := `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`
	responseBody, statusCode, err := proxy.Forward([]byte(requestBody))
	
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if statusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", statusCode, http.StatusOK)
	}
	
	var response JSONRPCResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	
	if response.Result != "0x123" {
		t.Errorf("got result %v, want 0x123", response.Result)
	}
}
