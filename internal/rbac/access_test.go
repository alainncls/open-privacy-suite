package rbac

import (
	"testing"
)

func TestClassifyOperation(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		params         []any
		expectedClaims []Claim
	}{
		{
			name:           "Read operation - eth_call",
			method:         "eth_call",
			params:         nil,
			expectedClaims: []Claim{ClaimReader},
		},
		{
			name:           "Read operation - eth_getBalance",
			method:         "eth_getBalance",
			params:         nil,
			expectedClaims: []Claim{ClaimReader},
		},
		{
			name:           "Read operation - eth_blockNumber",
			method:         "eth_blockNumber",
			params:         nil,
			expectedClaims: []Claim{ClaimReader},
		},
		{
			name:           "Write operation - eth_sendRawTransaction",
			method:         "eth_sendRawTransaction",
			params:         nil,
			expectedClaims: []Claim{ClaimWriter},
		},
		{
			name:   "Write operation - eth_sendTransaction with to",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234", "value": "0x100"},
			},
			expectedClaims: []Claim{ClaimWriter},
		},
		{
			name:   "Deploy operation - eth_sendTransaction without to",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x1234"},
			},
			expectedClaims: []Claim{ClaimDeployer},
		},
		{
			name:   "Deploy operation - eth_sendTransaction with empty to",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "", "data": "0x1234"},
			},
			expectedClaims: []Claim{ClaimDeployer},
		},
		{
			name:   "Deploy operation - eth_sendTransaction with nil to",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "data": "0x1234"},
			},
			expectedClaims: []Claim{ClaimDeployer},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := ClassifyOperation(tt.method, tt.params)

			if len(claims) != len(tt.expectedClaims) {
				t.Errorf("Expected %d claims, got %d", len(tt.expectedClaims), len(claims))
				return
			}

			for i, expected := range tt.expectedClaims {
				if claims[i] != expected {
					t.Errorf("Expected claim %v at index %d, got %v", expected, i, claims[i])
				}
			}
		})
	}
}

func TestGetTargetAddress(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		{
			name:     "No params",
			method:   "eth_call",
			params:   nil,
			expected: "",
		},
		{
			name:     "Empty params",
			method:   "eth_call",
			params:   []any{},
			expected: "",
		},
		{
			name:   "eth_call with to address",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0xABCD1234"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_estimateGas with to address",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0xABCD1234", "data": "0x"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_sendTransaction with to address",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0xABCD1234", "value": "0x100"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_getCode with address",
			method: "eth_getCode",
			params: []any{"0xABCD1234", "latest"},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_getBalance with address",
			method: "eth_getBalance",
			params: []any{"0xABCD1234", "latest"},
			expected: "0xabcd1234",
		},
		{
			name:     "Unknown method",
			method:   "eth_blockNumber",
			params:   []any{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTargetAddress(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestEffectivePermissionsMethods(t *testing.T) {
	perms := &EffectivePermissions{
		AllowMethods:   []string{"eth_call", "eth_getBalance"},
		AllowAddresses: []string{"0xaddress1", "0xaddress2"},
		OwnedAddresses: []string{"0xowned1"},
		Claims:         []Claim{ClaimReader, ClaimWriter},
	}

	// Test HasMethod
	if !perms.HasMethod("eth_call") {
		t.Error("Expected HasMethod to return true for eth_call")
	}
	if perms.HasMethod("eth_sendTransaction") {
		t.Error("Expected HasMethod to return false for eth_sendTransaction")
	}

	// Test HasAddress
	if !perms.HasAddress("0xaddress1") {
		t.Error("Expected HasAddress to return true for 0xaddress1")
	}
	if perms.HasAddress("0xunknown") {
		t.Error("Expected HasAddress to return false for unknown address")
	}

	// Test OwnsAddress
	if !perms.OwnsAddress("0xowned1") {
		t.Error("Expected OwnsAddress to return true for 0xowned1")
	}
	if perms.OwnsAddress("0xaddress1") {
		t.Error("Expected OwnsAddress to return false for allowed but not owned address")
	}

	// Test HasClaim
	if !perms.HasClaim(ClaimReader) {
		t.Error("Expected HasClaim to return true for reader")
	}
	if !perms.HasClaim(ClaimWriter) {
		t.Error("Expected HasClaim to return true for writer")
	}
	if perms.HasClaim(ClaimDeployer) {
		t.Error("Expected HasClaim to return false for deployer")
	}
}

func TestIsMethodBlocked(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected bool
	}{
		// Should be blocked - debug namespace
		{"debug_traceTransaction", "debug_traceTransaction", true},
		{"debug_setHead", "debug_setHead", true},
		{"debug_unknown", "debug_unknown", true}, // prefix match

		// Should be blocked - admin namespace
		{"admin_addPeer", "admin_addPeer", true},
		{"admin_nodeInfo", "admin_nodeInfo", true},
		{"admin_unknown", "admin_unknown", true}, // prefix match

		// Should be blocked - personal namespace
		{"personal_unlockAccount", "personal_unlockAccount", true},
		{"personal_sign", "personal_sign", true},
		{"personal_unknown", "personal_unknown", true}, // prefix match

		// Should be blocked - miner namespace
		{"miner_start", "miner_start", true},
		{"miner_stop", "miner_stop", true},

		// Should be blocked - txpool namespace
		{"txpool_content", "txpool_content", true},
		{"txpool_status", "txpool_status", true},

		// Should be blocked - signing methods
		{"eth_sign", "eth_sign", true},
		{"eth_signTransaction", "eth_signTransaction", true},

		// Should be blocked - clique namespace
		{"clique_propose", "clique_propose", true},

		// Should be blocked - les namespace
		{"les_serverInfo", "les_serverInfo", true},

		// Should NOT be blocked - normal read operations
		{"eth_call", "eth_call", false},
		{"eth_getBalance", "eth_getBalance", false},
		{"eth_blockNumber", "eth_blockNumber", false},
		{"eth_getTransactionReceipt", "eth_getTransactionReceipt", false},
		{"eth_chainId", "eth_chainId", false},

		// Should NOT be blocked - normal write operations
		{"eth_sendTransaction", "eth_sendTransaction", false},
		{"eth_sendRawTransaction", "eth_sendRawTransaction", false},

		// Should NOT be blocked - other namespaces
		{"net_version", "net_version", false},
		{"web3_clientVersion", "web3_clientVersion", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMethodBlocked(tt.method)
			if result != tt.expected {
				t.Errorf("IsMethodBlocked(%q) = %v, expected %v", tt.method, result, tt.expected)
			}
		})
	}
}

func TestIsMulticallTarget(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected bool
	}{
		{"Multicall3 lowercase", "0xca11bde05977b3631167028862be2a173976ca11", true},
		{"Multicall3 uppercase", "0xCA11BDE05977B3631167028862BE2A173976CA11", true},
		{"Multicall3 mixed case", "0xcA11bde05977b3631167028862bE2a173976CA11", true},
		{"Multicall2 mainnet", "0x5ba1e12693dc8f9c48aad8770482f4739beed696", true},
		{"Original Multicall", "0xeefba1e63905ef1d7acba5a8513c70307c1ce441", true},
		{"Random address", "0x1234567890123456789012345678901234567890", false},
		{"Empty address", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMulticallTarget(tt.address)
			if result != tt.expected {
				t.Errorf("IsMulticallTarget(%q) = %v, expected %v", tt.address, result, tt.expected)
			}
		})
	}
}

func TestIsMulticallData(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{"aggregate selector", "0x252dba42", true},
		{"aggregate3 selector", "0x82ad56cb", true},
		{"tryAggregate selector", "0xbce38bd7", true},
		{"aggregate with params", "0x252dba42000000000000000000000000", true},
		{"Not multicall", "0xa9059cbb", false},
		{"Empty data", "", false},
		{"Short data", "0x1234", false},
		{"No 0x prefix", "252dba42", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMulticallData(tt.data)
			if result != tt.expected {
				t.Errorf("IsMulticallData(%q) = %v, expected %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestDetectMulticall(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		params          []any
		expectMulticall bool
	}{
		{
			name:   "eth_call to Multicall3 with aggregate",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to":   "0xcA11bde05977b3631167028862bE2a173976CA11",
					"data": "0x252dba42000000000000000000000000",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_estimateGas to Multicall3",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0x82ad56cb",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_call to regular contract",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to":   "0x1234567890123456789012345678901234567890",
					"data": "0x252dba42",
				},
			},
			expectMulticall: false,
		},
		{
			name:   "eth_call to Multicall3 with non-multicall function",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0xa9059cbb", // transfer selector
				},
			},
			expectMulticall: false,
		},
		{
			name:            "eth_sendTransaction is not checked",
			method:          "eth_sendTransaction",
			params:          []any{},
			expectMulticall: false,
		},
		{
			name:            "eth_blockNumber is not checked",
			method:          "eth_blockNumber",
			params:          []any{},
			expectMulticall: false,
		},
		{
			name:            "Empty params",
			method:          "eth_call",
			params:          []any{},
			expectMulticall: false,
		},
		{
			name:   "Missing data field",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to": "0xca11bde05977b3631167028862be2a173976ca11",
				},
			},
			expectMulticall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isMulticall, reason := DetectMulticall(tt.method, tt.params)
			if isMulticall != tt.expectMulticall {
				t.Errorf("DetectMulticall() = %v, expected %v, reason: %s", isMulticall, tt.expectMulticall, reason)
			}
			if tt.expectMulticall && reason == "" {
				t.Error("Expected non-empty reason when Multicall is detected")
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("intersectStrings", func(t *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"b", "c", "d"}
		result := intersectStrings(a, b)

		if len(result) != 2 {
			t.Errorf("Expected 2 elements, got %d: %v", len(result), result)
		}
	})

	t.Run("intersectStrings empty", func(t *testing.T) {
		result := intersectStrings([]string{}, []string{"a", "b"})
		if len(result) != 0 {
			t.Errorf("Expected empty result, got %v", result)
		}
	})

	t.Run("unionStrings", func(t *testing.T) {
		a := []string{"a", "b"}
		b := []string{"b", "c"}
		result := unionStrings(a, b)

		if len(result) != 3 {
			t.Errorf("Expected 3 elements, got %d: %v", len(result), result)
		}
	})

	t.Run("minIntPtr both non-nil", func(t *testing.T) {
		a := 10
		b := 5
		result := minIntPtr(&a, &b)
		if result == nil || *result != 5 {
			t.Errorf("Expected 5, got %v", result)
		}
	})

	t.Run("minIntPtr one nil", func(t *testing.T) {
		a := 10
		result := minIntPtr(&a, nil)
		if result == nil || *result != 10 {
			t.Errorf("Expected 10, got %v", result)
		}
	})

	t.Run("minIntPtr both nil", func(t *testing.T) {
		result := minIntPtr(nil, nil)
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})

	t.Run("maxIntPtr both non-nil", func(t *testing.T) {
		a := 10
		b := 5
		result := maxIntPtr(&a, &b)
		if result == nil || *result != 10 {
			t.Errorf("Expected 10, got %v", result)
		}
	})

	t.Run("maxIntPtr one nil (unlimited)", func(t *testing.T) {
		a := 10
		result := maxIntPtr(&a, nil)
		if result != nil {
			t.Errorf("Expected nil (unlimited), got %v", result)
		}
	})
}
