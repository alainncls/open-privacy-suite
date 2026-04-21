package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsBatchRequest(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Single request",
			body:     `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			expected: false,
		},
		{
			name:     "Batch request",
			body:     `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_getBalance","params":[],"id":2}]`,
			expected: true,
		},
		{
			name:     "Empty batch",
			body:     `[]`,
			expected: true,
		},
		{
			name:     "Whitespace before array",
			body:     `  [{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}]`,
			expected: true,
		},
		{
			name:     "Newlines before array",
			body:     "\n\t[{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[],\"id\":1}]",
			expected: true,
		},
		{
			name:     "Whitespace before object",
			body:     `  {"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			expected: false,
		},
		{
			name:     "Empty body",
			body:     ``,
			expected: false,
		},
		{
			name:     "Whitespace only",
			body:     `   `,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBatchRequest([]byte(tt.body))
			if result != tt.expected {
				t.Errorf("IsBatchRequest(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

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
		{
			name:    "batch request should error",
			body:    `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}]`,
			want:    "",
			wantErr: true, // Batch requests return ErrBatchRequest
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

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod string
		wantErr    bool
		errType    error
	}{
		{
			name:       "valid request",
			body:       `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			wantMethod: "eth_call",
			wantErr:    false,
		},
		{
			name:       "request with params",
			body:       `{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x123", "latest"],"id":2}`,
			wantMethod: "eth_getBalance",
			wantErr:    false,
		},
		{
			name:       "invalid JSON",
			body:       `{"jsonrpc":"2.0"`,
			wantMethod: "",
			wantErr:    true,
		},
		{
			name:       "batch request",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}]`,
			wantMethod: "",
			wantErr:    true,
			errType:    ErrBatchRequest,
		},
		{
			name:       "batch request multiple",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_getBalance","params":[],"id":2}]`,
			wantMethod: "",
			wantErr:    true,
			errType:    ErrBatchRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, _, err := ParseRequest([]byte(tt.body))

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("expected error %v, got %v", tt.errType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if method != tt.wantMethod {
				t.Errorf("got method %q, want %q", method, tt.wantMethod)
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

// TestForward_ResponseSizeLimit verifies that the proxy caps upstream JSON-RPC
// responses at maxRPCResponseSize and returns a 502 error when an upstream
// writes more than that. Small responses must still succeed unchanged.
func TestForward_ResponseSizeLimit(t *testing.T) {
	t.Run("small response passes through", func(t *testing.T) {
		small := `{"jsonrpc":"2.0","result":"0xabc","id":1}`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(small))
		}))
		defer server.Close()

		p := New(server.URL)
		body, status, err := p.Forward([]byte(`{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`))
		if err != nil {
			t.Fatalf("unexpected error for small response: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("got status %d, want 200", status)
		}
		if string(body) != small {
			t.Errorf("got body %q, want %q", body, small)
		}
	})

	t.Run("response over limit is rejected with 502", func(t *testing.T) {
		// Write exactly maxRPCResponseSize + 100 bytes so io.LimitReader(+1)
		// sees more than the cap. Stream the body to avoid a monster
		// intermediate buffer allocation in the test.
		const oversize = maxRPCResponseSize + 100
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			chunk := bytes.Repeat([]byte{'x'}, 1<<20) // 1 MiB
			written := 0
			for written < oversize {
				n := oversize - written
				if n > len(chunk) {
					n = len(chunk)
				}
				if _, err := w.Write(chunk[:n]); err != nil {
					return
				}
				written += n
			}
		}))
		defer server.Close()

		p := New(server.URL)
		body, status, err := p.Forward([]byte(`{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`))
		if err == nil {
			t.Fatal("expected error for oversized response, got nil")
		}
		if status != http.StatusBadGateway {
			t.Errorf("got status %d, want 502", status)
		}
		if body != nil {
			t.Errorf("expected nil body on oversize error, got %d bytes", len(body))
		}
		if !strings.Contains(err.Error(), "exceeded") {
			t.Errorf("expected error to mention the limit, got %q", err.Error())
		}
	})

	t.Run("response at exact limit is accepted", func(t *testing.T) {
		const exact = maxRPCResponseSize
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			chunk := bytes.Repeat([]byte{'y'}, 1<<20)
			written := 0
			for written < exact {
				n := exact - written
				if n > len(chunk) {
					n = len(chunk)
				}
				if _, err := w.Write(chunk[:n]); err != nil {
					return
				}
				written += n
			}
		}))
		defer server.Close()

		p := New(server.URL)
		body, status, err := p.Forward([]byte(`{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`))
		if err != nil {
			t.Fatalf("unexpected error for exact-limit response: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("got status %d, want 200", status)
		}
		if len(body) != exact {
			t.Errorf("got body len %d, want %d", len(body), exact)
		}
	})
}
