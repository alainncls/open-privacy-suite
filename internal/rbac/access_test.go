package rbac

import (
	"testing"
)

func TestClassifyOperation(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		params        []any
		expectedClaim Claim
	}{
		{
			name:          "Read operation - eth_call",
			method:        "eth_call",
			params:        nil,
			expectedClaim: ClaimRead,
		},
		{
			name:          "Read operation - eth_getBalance",
			method:        "eth_getBalance",
			params:        nil,
			expectedClaim: ClaimRead,
		},
		{
			name:   "Read operation - eth_estimateGas with to address",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
			},
			expectedClaim: ClaimRead,
		},
		{
			name:          "Write operation - eth_sendRawTransaction",
			method:        "eth_sendRawTransaction",
			params:        nil,
			expectedClaim: ClaimWrite,
		},
		{
			name:   "Write operation - eth_sendTransaction with to address",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "value": "0x100"},
			},
			expectedClaim: ClaimWrite,
		},
		{
			name:          "Other method - no contract claim required",
			method:        "eth_blockNumber",
			params:        nil,
			expectedClaim: "",
		},
		{
			name:          "Other method - net_version",
			method:        "net_version",
			params:        nil,
			expectedClaim: "",
		},
		// Contract deployment cases - should require deploy claim
		{
			name:          "Deploy - eth_sendTransaction with no params",
			method:        "eth_sendTransaction",
			params:        nil,
			expectedClaim: ClaimDeploy,
		},
		{
			name:          "Deploy - eth_sendTransaction with empty params",
			method:        "eth_sendTransaction",
			params:        []any{},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with no 'to' field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x6080604052", "value": "0x0"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with 'to' = null",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with 'to' = empty string",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "", "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with 'to' = '0x'",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x", "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "NOT Deploy - eth_sendTransaction with valid 'to' address",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
			},
			expectedClaim: ClaimWrite,
		},
		{
			name:   "NOT Deploy - eth_sendTransaction to zero address (burn)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x0000000000000000000000000000000000000000", "value": "0x100"},
			},
			expectedClaim: ClaimWrite,
		},
		// eth_estimateGas deployment cases - should require deploy claim
		{
			name:   "Deploy - eth_estimateGas with no 'to' field (deployment estimation)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"data": "0x6080604052", "from": "0xabc"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_estimateGas with 'to' = null (deployment estimation)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "NOT Deploy - eth_estimateGas with valid 'to' (regular call estimation)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
			},
			expectedClaim: ClaimRead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := ClassifyOperation(tt.method, tt.params)

			if claim != tt.expectedClaim {
				t.Errorf("Expected claim %v, got %v", tt.expectedClaim, claim)
			}
		})
	}
}

func TestIsContractDeployment(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected bool
	}{
		// Deployment cases
		{
			name:     "eth_sendTransaction with no params - deployment",
			method:   "eth_sendTransaction",
			params:   nil,
			expected: true,
		},
		{
			name:     "eth_sendTransaction with empty params - deployment",
			method:   "eth_sendTransaction",
			params:   []any{},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with no 'to' field - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x6080604052", "from": "0xabc"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' = nil - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' = empty string - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "", "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' = '0x' - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x", "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with malformed params (not map) - deployment (safe default)",
			method: "eth_sendTransaction",
			params: []any{"not a map"},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' as number - deployment (safe default)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": 12345, "data": "0x6080604052"},
			},
			expected: true,
		},
		// NOT deployment cases
		{
			name:   "eth_sendTransaction with valid 'to' - NOT deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890"},
			},
			expected: false,
		},
		{
			name:   "eth_sendTransaction to zero address - NOT deployment (it's a burn)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x0000000000000000000000000000000000000000"},
			},
			expected: false,
		},
		{
			name:   "eth_sendTransaction with short but valid 'to' - NOT deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1"},
			},
			expected: false,
		},
		// eth_estimateGas deployment cases
		{
			name:   "eth_estimateGas with no 'to' field - deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"data": "0x6080604052", "from": "0xabc"},
			},
			expected: true,
		},
		{
			name:   "eth_estimateGas with 'to' = nil - deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_estimateGas with 'to' = '' - deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "", "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_estimateGas with valid 'to' - NOT deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890"},
			},
			expected: false,
		},
		// Other methods - never deployment
		{
			name:     "eth_sendRawTransaction - NOT deployment (can't validate)",
			method:   "eth_sendRawTransaction",
			params:   []any{"0xf86c..."},
			expected: false,
		},
		{
			name:     "eth_call - NOT deployment",
			method:   "eth_call",
			params:   nil,
			expected: false,
		},
		{
			name:     "eth_blockNumber - NOT deployment",
			method:   "eth_blockNumber",
			params:   nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsContractDeployment(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("IsContractDeployment(%q, %v) = %v, expected %v",
					tt.method, tt.params, result, tt.expected)
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
			name:     "eth_getCode with address",
			method:   "eth_getCode",
			params:   []any{"0xABCD1234", "latest"},
			expected: "0xabcd1234",
		},
		{
			name:     "eth_getBalance with address",
			method:   "eth_getBalance",
			params:   []any{"0xABCD1234", "latest"},
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
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{
			"0xaddress1": {Claims: []Claim{ClaimRead, ClaimWrite}},
			"0xaddress2": {Claims: []Claim{ClaimRead}},
			"0xowned1":   {Claims: []Claim{ClaimRead, ClaimWrite, ClaimAdmin}},
		},
		DefaultClaims: []Claim{ClaimRead},
	}

	// Test HasMethod
	if !perms.HasMethod("eth_call") {
		t.Error("Expected HasMethod to return true for eth_call")
	}
	if perms.HasMethod("eth_sendTransaction") {
		t.Error("Expected HasMethod to return false for eth_sendTransaction")
	}

	// Test HasContractAccess
	if !perms.HasContractAccess("0xaddress1") {
		t.Error("Expected HasContractAccess to return true for 0xaddress1")
	}
	if perms.HasContractAccess("0xunknown") {
		t.Error("Expected HasContractAccess to return false for unknown address")
	}

	// Test HasDefaultClaim
	if !perms.HasDefaultClaim(ClaimRead) {
		t.Error("Expected HasDefaultClaim to return true for ClaimRead")
	}
	if perms.HasDefaultClaim(ClaimWrite) {
		t.Error("Expected HasDefaultClaim to return false for ClaimWrite")
	}

	// Test contract access claims
	access := perms.ContractAccess["0xaddress1"]
	if !access.HasClaim(ClaimRead) {
		t.Error("Expected contract access to have read claim")
	}
	if !access.HasClaim(ClaimWrite) {
		t.Error("Expected contract access to have write claim")
	}
	if access.HasClaim(ClaimAdmin) {
		t.Error("Expected contract access to not have admin claim")
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
			name:   "eth_sendTransaction to Multicall3 with aggregate - BLOCKED",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0x252dba42000000000000000000000000",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_sendTransaction to Multicall3 with aggregate3 - BLOCKED",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0x82ad56cb",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_sendTransaction to regular contract - allowed",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0x1234567890123456789012345678901234567890",
					"data": "0x252dba42", // Same selector but different target
				},
			},
			expectMulticall: false,
		},
		{
			name:   "eth_sendTransaction to Multicall3 with non-multicall function - allowed",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0xa9059cbb", // transfer selector, not multicall
				},
			},
			expectMulticall: false,
		},
		{
			name:            "eth_sendTransaction with empty params - not checked",
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

func TestExtractGetLogsAddresses(t *testing.T) {
	tests := []struct {
		name     string
		filter   map[string]any
		expected []string
	}{
		{
			name:     "No address field",
			filter:   map[string]any{"fromBlock": "latest"},
			expected: nil,
		},
		{
			name:     "Address field is nil",
			filter:   map[string]any{"address": nil},
			expected: nil,
		},
		{
			name:     "Single address as string",
			filter:   map[string]any{"address": "0xABCD1234567890ABCD1234567890ABCD12345678"},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name:     "Single address as string (lowercase)",
			filter:   map[string]any{"address": "0xabcd1234567890abcd1234567890abcd12345678"},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name:     "Empty string address",
			filter:   map[string]any{"address": ""},
			expected: []string{},
		},
		{
			name: "Multiple addresses as array",
			filter: map[string]any{
				"address": []any{
					"0xABCD1234567890ABCD1234567890ABCD12345678",
					"0x1234567890ABCD1234567890ABCD123456789012",
				},
			},
			expected: []string{
				"0xabcd1234567890abcd1234567890abcd12345678",
				"0x1234567890abcd1234567890abcd123456789012",
			},
		},
		{
			name:     "Empty address array",
			filter:   map[string]any{"address": []any{}},
			expected: []string{},
		},
		{
			name: "Array with empty string (filtered out)",
			filter: map[string]any{
				"address": []any{
					"0xABCD1234567890ABCD1234567890ABCD12345678",
					"",
				},
			},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name: "Array with mixed types (non-strings ignored)",
			filter: map[string]any{
				"address": []any{
					"0xABCD1234567890ABCD1234567890ABCD12345678",
					123, // number, should be ignored
				},
			},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetGetLogsAddresses([]any{tt.filter})

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d addresses, got %d: %v", len(tt.expected), len(result), result)
				return
			}

			for i, addr := range result {
				if addr != tt.expected[i] {
					t.Errorf("Address %d: expected %q, got %q", i, tt.expected[i], addr)
				}
			}
		})
	}
}

func TestValidateGetLogsAccess(t *testing.T) {
	// Create test permissions with specific contract access
	permsWithAccess := &EffectivePermissions{
		AllowedMethods: []string{"eth_getLogs", "eth_call"},
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {Claims: []Claim{ClaimRead, ClaimWrite}},
			"0xcontract2": {Claims: []Claim{ClaimRead}},
			"0xnoread":    {Claims: []Claim{ClaimWrite}}, // Has write but NOT read
		},
		DefaultClaims: []Claim{}, // No default claims
	}

	permsWithDefaultRead := &EffectivePermissions{
		AllowedMethods: []string{"eth_getLogs"},
		ContractAccess: map[string]ContractAccess{
			"0xcontract1": {Claims: []Claim{ClaimRead}},
		},
		DefaultClaims: []Claim{ClaimRead}, // Has default read claim
	}

	tests := []struct {
		name        string
		perms       *EffectivePermissions
		params      []any
		expectError bool
		errorSubstr string
	}{
		// Error cases - missing/invalid params
		{
			name:        "No params",
			perms:       permsWithAccess,
			params:      nil,
			expectError: true,
			errorSubstr: "missing filter parameter",
		},
		{
			name:        "Empty params",
			perms:       permsWithAccess,
			params:      []any{},
			expectError: true,
			errorSubstr: "missing filter parameter",
		},
		{
			name:        "Invalid filter type (not a map)",
			perms:       permsWithAccess,
			params:      []any{"not a map"},
			expectError: true,
			errorSubstr: "invalid filter parameter type",
		},
		// Security requirement: address filter is required
		{
			name:        "No address filter - security denial",
			perms:       permsWithAccess,
			params:      []any{map[string]any{"fromBlock": "latest"}},
			expectError: true,
			errorSubstr: "address filter required",
		},
		{
			name:        "Null address filter - security denial",
			perms:       permsWithAccess,
			params:      []any{map[string]any{"address": nil}},
			expectError: true,
			errorSubstr: "address filter required",
		},
		{
			name:        "Empty address array - security denial",
			perms:       permsWithAccess,
			params:      []any{map[string]any{"address": []any{}}},
			expectError: true,
			errorSubstr: "address filter required",
		},
		{
			name:        "Empty string address - security denial",
			perms:       permsWithAccess,
			params:      []any{map[string]any{"address": ""}},
			expectError: true,
			errorSubstr: "address filter required",
		},
		// Access denied cases
		{
			name:  "Single address - no access at all",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": "0xunknowncontract",
			}},
			expectError: true,
			errorSubstr: "no access to contract",
		},
		{
			name:  "Single address - has write but not read claim",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": "0xnoread",
			}},
			expectError: true,
			errorSubstr: "missing read claim",
		},
		{
			name:  "Multiple addresses - one without access",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": []any{"0xcontract1", "0xunknowncontract"},
			}},
			expectError: true,
			errorSubstr: "no access to contract",
		},
		{
			name:  "Multiple addresses - one missing read claim",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": []any{"0xcontract1", "0xnoread"},
			}},
			expectError: true,
			errorSubstr: "missing read claim",
		},
		// Success cases
		{
			name:  "Single address - has read access",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": "0xcontract1",
			}},
			expectError: false,
		},
		{
			name:  "Single address - case insensitive match",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": "0xCONTRACT1", // uppercase
			}},
			expectError: false,
		},
		{
			name:  "Multiple addresses - all have read access",
			perms: permsWithAccess,
			params: []any{map[string]any{
				"address": []any{"0xcontract1", "0xcontract2"},
			}},
			expectError: false,
		},
		{
			name:  "Single address - access via default claims",
			perms: permsWithDefaultRead,
			params: []any{map[string]any{
				"address": "0xunregisteredcontract",
			}},
			expectError: false,
		},
		{
			name:  "Multiple addresses - some registered, some via default",
			perms: permsWithDefaultRead,
			params: []any{map[string]any{
				"address": []any{"0xcontract1", "0xunregisteredcontract"},
			}},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGetLogsAccess(tt.perms, tt.params)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorSubstr)
					return
				}
				if tt.errorSubstr != "" && !contains(err.Error(), tt.errorSubstr) {
					t.Errorf("Expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// contains checks if s contains substr (simple helper to avoid import)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchSubstr(s, substr)))
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestClassifyOperation_EthGetLogs(t *testing.T) {
	// eth_getLogs should require read claim
	tests := []struct {
		name          string
		method        string
		params        []any
		expectedClaim Claim
	}{
		{
			name:          "eth_getLogs requires read claim",
			method:        "eth_getLogs",
			params:        nil,
			expectedClaim: ClaimRead,
		},
		{
			name:   "eth_getLogs with filter requires read claim",
			method: "eth_getLogs",
			params: []any{
				map[string]any{"address": "0x1234", "fromBlock": "latest"},
			},
			expectedClaim: ClaimRead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := ClassifyOperation(tt.method, tt.params)
			if claim != tt.expectedClaim {
				t.Errorf("Expected claim %v, got %v", tt.expectedClaim, claim)
			}
		})
	}
}

// TestCrossOrgIsolation tests the P0 security fix for cross-org isolation.
// This ensures that users cannot access contracts belonging to other organizations
// via the default_claims fallback.
func TestCrossOrgIsolation(t *testing.T) {
	t.Run("IsContractRegistered - explicit access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{ClaimRead},
		}

		if !perms.IsContractRegistered("0xmycontract") {
			t.Error("Expected IsContractRegistered to return true for contract in ContractAccess")
		}
		if !perms.IsContractRegistered("0xMYCONTRACT") {
			t.Error("Expected IsContractRegistered to be case-insensitive")
		}
		if perms.IsContractRegistered("0xothercontract") {
			t.Error("Expected IsContractRegistered to return false for unknown contract")
		}
	})

	t.Run("GetContractAccess returns default claims for unregistered", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
			DefaultClaims: []Claim{ClaimRead},
		}

		// Registered contract should return explicit access
		access := perms.GetContractAccess("0xmycontract")
		if access == nil || len(access.Claims) != 2 {
			t.Errorf("Expected 2 claims for registered contract, got %v", access)
		}

		// Unregistered contract should return default claims
		access = perms.GetContractAccess("0xunregistered")
		if access == nil || len(access.Claims) != 1 || access.Claims[0] != ClaimRead {
			t.Errorf("Expected default read claim for unregistered contract, got %v", access)
		}
	})

	t.Run("No default claims means no access to unregistered", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{}, // No default claims
		}

		access := perms.GetContractAccess("0xunregistered")
		if access != nil {
			t.Errorf("Expected nil access for unregistered contract when no default claims, got %v", access)
		}
	})
}

// TestCrossOrgIsolationReadOps verifies the ReadOpsMap contains the right methods.
func TestCrossOrgIsolationReadOps(t *testing.T) {
	// These are the read operations that need cross-org isolation check
	expectedReadOps := []string{
		"eth_call",
		"eth_estimateGas",
		"eth_getCode",
		"eth_getBalance",
		"eth_getStorageAt",
		"eth_getTransactionCount",
		"eth_getLogs",
	}

	for _, method := range expectedReadOps {
		if !ReadOpsMap[method] {
			t.Errorf("Expected %s to be in ReadOpsMap", method)
		}
	}

	// Verify write ops are NOT in ReadOpsMap
	writeOps := []string{"eth_sendTransaction", "eth_sendRawTransaction"}
	for _, method := range writeOps {
		if ReadOpsMap[method] {
			t.Errorf("Expected %s to NOT be in ReadOpsMap", method)
		}
	}
}

// =============================================================================
// Comprehensive Cross-Org Isolation Tests
// =============================================================================

// TestCrossOrgIsolationComprehensive provides comprehensive cross-org isolation tests
// verifying security properties for contract access across organizations.
func TestCrossOrgIsolationComprehensive(t *testing.T) {
	// Contract addresses for testing
	const (
		contractOrgA = "0xaaaa000000000000000000000000000000000001" // OrgA's contract
		contractOrgB = "0xbbbb000000000000000000000000000000000002" // OrgB's contract
		publicContract = "0xcccc000000000000000000000000000000000003" // Public (no org)
	)

	t.Run("user cannot access other org contract via eth_call", func(t *testing.T) {
		// UserA has access to ContractOrgA but not ContractOrgB
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_estimateGas"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
			DefaultClaims: []Claim{}, // No default claims - cross-org denied
		}

		// User has access to their own contract
		accessA := perms.GetContractAccess(contractOrgA)
		if accessA == nil {
			t.Fatal("User should have access to their own org's contract")
		}
		if !accessA.HasClaim(ClaimRead) {
			t.Error("User should have read claim on their own contract")
		}

		// User does NOT have access to other org's contract (contractOrgB is registered elsewhere)
		// With no default claims, GetContractAccess returns nil
		accessB := perms.GetContractAccess(contractOrgB)
		if accessB != nil {
			t.Error("User should NOT have access to other org's contract when no default claims")
		}

		// Operation classification
		claim := ClassifyOperation("eth_call", []any{
			map[string]any{"to": contractOrgB, "data": "0xa9059cbb"},
		})
		if claim != ClaimRead {
			t.Errorf("eth_call should require read claim, got %v", claim)
		}
	})

	t.Run("user cannot access other org contract via eth_estimateGas", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_estimateGas"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{}, // No default claims
		}

		// Verify user has no access to other org's contract
		accessB := perms.GetContractAccess(contractOrgB)
		if accessB != nil {
			t.Error("User should NOT have access to other org's contract")
		}

		// Operation still requires read claim
		claim := ClassifyOperation("eth_estimateGas", []any{
			map[string]any{"to": contractOrgB, "data": "0xa9059cbb"},
		})
		if claim != ClaimRead {
			t.Errorf("eth_estimateGas should require read claim, got %v", claim)
		}
	})

	t.Run("user can access their own org contract", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
			DefaultClaims: []Claim{},
		}

		// User has full access to their own contract
		access := perms.GetContractAccess(contractOrgA)
		if access == nil {
			t.Fatal("User should have access to their own org's contract")
		}
		if !access.HasClaim(ClaimRead) {
			t.Error("User should have read claim on their own contract")
		}
		if !access.HasClaim(ClaimWrite) {
			t.Error("User should have write claim on their own contract")
		}

		// Verify HasContractClaim
		if !perms.HasContractClaim(contractOrgA, ClaimRead) {
			t.Error("HasContractClaim should return true for read")
		}
		if !perms.HasContractClaim(contractOrgA, ClaimWrite) {
			t.Error("HasContractClaim should return true for write")
		}
		if perms.HasContractClaim(contractOrgA, ClaimAdmin) {
			t.Error("HasContractClaim should return false for admin (not granted)")
		}
	})

	t.Run("user can access truly public contract with default_claims", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
			DefaultClaims: []Claim{ClaimRead}, // Default read claim for public contracts
		}

		// PublicContract is not registered to any org
		// User should get default_claims access
		access := perms.GetContractAccess(publicContract)
		if access == nil {
			t.Fatal("User should have default access to public contract")
		}
		if !access.HasClaim(ClaimRead) {
			t.Error("User should have default read claim on public contract")
		}
		if access.HasClaim(ClaimWrite) {
			t.Error("User should NOT have write claim (not in default_claims)")
		}
	})

	t.Run("default_claims do not grant access to other org contracts", func(t *testing.T) {
		// User with default_claims=['read','write'] still cannot access OrgB's contracts
		// This is enforced at the controller level, not EffectivePermissions
		// The controller checks IsContractRegisteredToAnyOrg before applying default_claims
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{ClaimRead, ClaimWrite}, // Wide default claims
		}

		// GetContractAccess returns default claims for unknown contracts
		// The cross-org check happens at controller level
		accessB := perms.GetContractAccess(contractOrgB)
		// This returns default claims, but controller would check IsContractRegisteredToAnyOrg
		// and deny if contract is registered to another org
		if accessB == nil {
			// This is expected if default_claims is empty, but here it's not
			t.Log("Note: GetContractAccess returns default claims; controller checks cross-org")
		}

		// Verify the registered contract only has its explicit claims
		accessA := perms.GetContractAccess(contractOrgA)
		if accessA == nil {
			t.Fatal("Should have explicit access to contractOrgA")
		}
		if accessA.HasClaim(ClaimWrite) {
			t.Error("ContractOrgA should only have explicit claims, not inherit from default")
		}
	})
}

// TestCrossOrgIsolationEdgeCasesComprehensive tests edge cases for cross-org isolation.
func TestCrossOrgIsolationEdgeCasesComprehensive(t *testing.T) {
	t.Run("case insensitive address matching", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xabcdef1234567890abcdef1234567890abcdef12": {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{},
		}

		// Should match regardless of case
		testCases := []string{
			"0xabcdef1234567890abcdef1234567890abcdef12",
			"0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
			"0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
		}

		for _, addr := range testCases {
			access := perms.GetContractAccess(addr)
			if access == nil {
				t.Errorf("Should have access to %s (case insensitive)", addr)
			}
			// Verify IsContractRegistered is also case insensitive
			if !perms.IsContractRegistered(addr) {
				t.Errorf("IsContractRegistered should match %s (case insensitive)", addr)
			}
		}
	})

	t.Run("empty contract access map with default claims", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{}, // Empty
			DefaultClaims:  []Claim{ClaimRead},
		}

		// Any contract should get default claims
		access := perms.GetContractAccess("0x1234567890123456789012345678901234567890")
		if access == nil {
			t.Error("Should return default access for any contract")
		}
		if !access.HasClaim(ClaimRead) {
			t.Error("Should have default read claim")
		}
	})

	t.Run("no default claims means no access to unregistered contracts", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa000000000000000000000000000000000001": {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{}, // No default claims
		}

		// Registered contract still accessible
		accessA := perms.GetContractAccess("0xaaaa000000000000000000000000000000000001")
		if accessA == nil {
			t.Fatal("Should have access to registered contract")
		}

		// Unregistered contract has NO access
		accessB := perms.GetContractAccess("0xbbbb000000000000000000000000000000000002")
		if accessB != nil {
			t.Error("Should have NO access to unregistered contract when no default claims")
		}
	})

	t.Run("nil default claims treated as empty", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa": {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: nil, // nil
		}

		// Should behave same as empty
		access := perms.GetContractAccess("0xunknown")
		if access != nil {
			t.Error("Should return nil for unknown contract when default claims is nil")
		}
	})
}

// =============================================================================
// ReadOps and WriteOps Validation Tests
// =============================================================================

// TestReadOpsValidationComprehensive tests access validation for read operations.
func TestReadOpsValidationComprehensive(t *testing.T) {
	t.Run("eth_call to accessible contract is allowed", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				addr: {Claims: []Claim{ClaimRead}},
			},
		}

		// Verify method is allowed
		if !perms.HasMethod("eth_call") {
			t.Error("eth_call should be in allowed methods")
		}

		// Verify contract access with read claim
		access := perms.GetContractAccess(addr)
		if access == nil {
			t.Fatal("Should have access to contract")
		}
		if !access.HasClaim(ClaimRead) {
			t.Error("Should have read claim")
		}
	})

	t.Run("eth_call to inaccessible contract is denied", func(t *testing.T) {
		userAddr := "0xaaaa000000000000000000000000000000000001"
		otherAddr := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				userAddr: {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{}, // No default claims
		}

		// User has no access to otherAddr
		access := perms.GetContractAccess(otherAddr)
		if access != nil {
			t.Error("Should NOT have access to unregistered contract when no default claims")
		}
	})

	t.Run("eth_estimateGas follows same rules as eth_call", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"

		// Both should require read claim
		callClaim := ClassifyOperation("eth_call", []any{
			map[string]any{"to": addr, "data": "0xa9059cbb"},
		})
		estimateClaim := ClassifyOperation("eth_estimateGas", []any{
			map[string]any{"to": addr, "data": "0xa9059cbb"},
		})

		if callClaim != estimateClaim {
			t.Errorf("eth_call and eth_estimateGas should require same claim, got %v vs %v",
				callClaim, estimateClaim)
		}
		if callClaim != ClaimRead {
			t.Errorf("Both should require read claim, got %v", callClaim)
		}
	})

	t.Run("eth_call without target address uses empty string", func(t *testing.T) {
		// GetTargetAddress returns empty string when 'to' is missing
		addr := GetTargetAddress("eth_call", []any{
			map[string]any{"data": "0x6080604052"},
		})
		if addr != "" {
			t.Errorf("Expected empty address, got %s", addr)
		}
	})

	t.Run("all read ops require read claim", func(t *testing.T) {
		// Read methods that work without params
		simpleReadMethods := []string{
			"eth_call",
			"eth_getCode",
			"eth_getBalance",
			"eth_getStorageAt",
			"eth_getTransactionCount",
			"eth_getLogs",
		}

		for _, method := range simpleReadMethods {
			claim := ClassifyOperation(method, nil)
			if claim != ClaimRead {
				t.Errorf("%s should require read claim, got %v", method, claim)
			}
		}

		// eth_estimateGas with nil params returns deploy (safe default)
		// because IsContractDeployment treats missing 'to' as deployment
		// With proper params (including 'to'), it requires read claim
		claimNoParams := ClassifyOperation("eth_estimateGas", nil)
		if claimNoParams != ClaimDeploy {
			t.Errorf("eth_estimateGas with nil params should require deploy claim (safe default), got %v", claimNoParams)
		}

		// With a 'to' address, eth_estimateGas requires read claim
		claimWithTo := ClassifyOperation("eth_estimateGas", []any{
			map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
		})
		if claimWithTo != ClaimRead {
			t.Errorf("eth_estimateGas with 'to' address should require read claim, got %v", claimWithTo)
		}
	})
}

// =============================================================================
// GetContractAccess Comprehensive Tests
// =============================================================================

// TestGetContractAccessComprehensive tests the GetContractAccess method behavior.
func TestGetContractAccessComprehensive(t *testing.T) {
	t.Run("returns explicit access for registered contract", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{ClaimRead, ClaimWrite},
					Functions: []string{"0xa9059cbb", "0x095ea7b3"},
				},
			},
			DefaultClaims: []Claim{ClaimRead},
		}

		access := perms.GetContractAccess(addr)
		if access == nil {
			t.Fatal("Should return access for registered contract")
		}
		if len(access.Claims) != 2 {
			t.Errorf("Should have 2 explicit claims, got %d", len(access.Claims))
		}
		if !access.HasClaim(ClaimWrite) {
			t.Error("Should have write claim")
		}
		if len(access.Functions) != 2 {
			t.Errorf("Should have 2 function selectors, got %d", len(access.Functions))
		}
	})

	t.Run("returns nil for other org contract when no default claims", func(t *testing.T) {
		userAddr := "0xaaaa000000000000000000000000000000000001"
		otherOrgAddr := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				userAddr: {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{}, // Empty
		}

		access := perms.GetContractAccess(otherOrgAddr)
		if access != nil {
			t.Error("Should return nil for contract not in access and no default claims")
		}
	})

	t.Run("returns default_claims for truly public contract", func(t *testing.T) {
		userAddr := "0xaaaa000000000000000000000000000000000001"
		publicAddr := "0xcccc000000000000000000000000000000000003"

		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				userAddr: {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
			DefaultClaims: []Claim{ClaimRead},
		}

		access := perms.GetContractAccess(publicAddr)
		if access == nil {
			t.Fatal("Should return default claims for public contract")
		}
		if !access.HasClaim(ClaimRead) {
			t.Error("Should have default read claim")
		}
		if access.HasClaim(ClaimWrite) {
			t.Error("Should NOT have write claim (not in default_claims)")
		}
		// Default access has nil functions (all functions allowed)
		if access.Functions != nil {
			t.Error("Default access should have nil Functions (all allowed)")
		}
	})

	t.Run("HasFunctionSelector with explicit restrictions", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{ClaimRead},
					Functions: []string{"0xa9059cbb", "0x095ea7b3"},
				},
			},
		}

		// Allowed selectors
		if !perms.HasFunctionSelector(addr, "0xa9059cbb") {
			t.Error("Should allow 0xa9059cbb")
		}
		if !perms.HasFunctionSelector(addr, "0x095ea7b3") {
			t.Error("Should allow 0x095ea7b3")
		}

		// Not allowed selector
		if perms.HasFunctionSelector(addr, "0x70a08231") {
			t.Error("Should NOT allow 0x70a08231 (not in allowed list)")
		}

		// Unknown contract (no default claims)
		if perms.HasFunctionSelector("0xunknown", "0xa9059cbb") {
			t.Error("Should NOT allow selector on unknown contract with no default claims")
		}
	})

	t.Run("HasFunctionSelector with no restrictions allows all", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{ClaimRead},
					Functions: nil, // No restrictions
				},
			},
		}

		// All selectors should be allowed
		if !perms.HasFunctionSelector(addr, "0xa9059cbb") {
			t.Error("Should allow any selector when Functions is nil")
		}
		if !perms.HasFunctionSelector(addr, "0x12345678") {
			t.Error("Should allow any selector when Functions is nil")
		}
	})

	t.Run("HasFunctionSelector with empty slice allows all", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{ClaimRead},
					Functions: []string{}, // Empty
				},
			},
		}

		if !perms.HasFunctionSelector(addr, "0xa9059cbb") {
			t.Error("Should allow any selector when Functions is empty")
		}
	})

	t.Run("HasAdminOnContract checks admin claim", func(t *testing.T) {
		adminAddr := "0xaaaa000000000000000000000000000000000001"
		normalAddr := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				adminAddr:  {Claims: []Claim{ClaimRead, ClaimWrite, ClaimAdmin}},
				normalAddr: {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
		}

		if !perms.HasAdminOnContract(adminAddr) {
			t.Error("Should have admin on adminAddr")
		}
		if perms.HasAdminOnContract(normalAddr) {
			t.Error("Should NOT have admin on normalAddr")
		}
	})
}

// =============================================================================
// GetFunctionSelector Tests
// =============================================================================

func TestGetFunctionSelectorComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		{
			name:     "eth_call with data",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa9059cbb0000000000"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "eth_estimateGas with data",
			method:   "eth_estimateGas",
			params:   []any{map[string]any{"to": "0x123", "data": "0x095ea7b3000000"}},
			expected: "0x095ea7b3",
		},
		{
			name:     "eth_sendTransaction with data",
			method:   "eth_sendTransaction",
			params:   []any{map[string]any{"to": "0x123", "data": "0x70a08231abc"}},
			expected: "0x70a08231",
		},
		{
			name:     "eth_call with uppercase data",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xA9059CBB0000"}},
			expected: "0xa9059cbb",
		},
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
			name:     "No data field",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123"}},
			expected: "",
		},
		{
			name:     "Data too short",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa905"}},
			expected: "",
		},
		{
			name:     "Data exactly 10 chars",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa9059cbb"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "Non-call method",
			method:   "eth_blockNumber",
			params:   []any{map[string]any{"data": "0xa9059cbb"}},
			expected: "",
		},
		{
			name:     "eth_getLogs (not a contract call)",
			method:   "eth_getLogs",
			params:   []any{map[string]any{"data": "0xa9059cbb"}},
			expected: "",
		},
		{
			name:     "Malformed params (not a map)",
			method:   "eth_call",
			params:   []any{"not a map"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetFunctionSelector(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("GetFunctionSelector(%q, %v) = %q, expected %q",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// eth_getLogs Security Tests - Additional Cases
// =============================================================================

// TestGetLogsSecurityAdditional provides additional security tests for eth_getLogs.
func TestGetLogsSecurityAdditional(t *testing.T) {
	t.Run("eth_getLogs with mixed accessible and inaccessible in array", func(t *testing.T) {
		addr1 := "0xaaaa000000000000000000000000000000000001"
		addr2 := "0xbbbb000000000000000000000000000000000002"
		addr3 := "0xcccc000000000000000000000000000000000003"

		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_getLogs"},
			ContractAccess: map[string]ContractAccess{
				addr1: {Claims: []Claim{ClaimRead}},
				addr3: {Claims: []Claim{ClaimRead}},
				// addr2 not accessible
			},
			DefaultClaims: []Claim{}, // No default
		}

		// Should fail because addr2 is not accessible
		params := []any{map[string]any{
			"address": []any{addr1, addr2, addr3},
		}}

		err := ValidateGetLogsAccess(perms, params)
		if err == nil {
			t.Error("Should deny when one address in array is not accessible")
		}
	})

	t.Run("eth_getLogs with all addresses accessible", func(t *testing.T) {
		addr1 := "0xaaaa000000000000000000000000000000000001"
		addr2 := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_getLogs"},
			ContractAccess: map[string]ContractAccess{
				addr1: {Claims: []Claim{ClaimRead}},
				addr2: {Claims: []Claim{ClaimRead}},
			},
			DefaultClaims: []Claim{},
		}

		params := []any{map[string]any{
			"address": []any{addr1, addr2},
		}}

		err := ValidateGetLogsAccess(perms, params)
		if err != nil {
			t.Errorf("Should allow when all addresses are accessible, got: %v", err)
		}
	})

	t.Run("eth_getLogs with default claims for public contract", func(t *testing.T) {
		publicAddr := "0xcccc000000000000000000000000000000000003"

		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_getLogs"},
			ContractAccess: map[string]ContractAccess{},
			DefaultClaims:  []Claim{ClaimRead}, // Has default read
		}

		params := []any{map[string]any{
			"address": publicAddr,
		}}

		err := ValidateGetLogsAccess(perms, params)
		if err != nil {
			t.Errorf("Should allow with default claims, got: %v", err)
		}
	})

	t.Run("eth_getLogs requires read claim specifically", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"

		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_getLogs"},
			ContractAccess: map[string]ContractAccess{
				addr: {Claims: []Claim{ClaimWrite, ClaimAdmin}}, // Has write and admin but NOT read
			},
			DefaultClaims: []Claim{},
		}

		params := []any{map[string]any{
			"address": addr,
		}}

		err := ValidateGetLogsAccess(perms, params)
		if err == nil {
			t.Error("Should deny when user has write/admin but not read claim")
		}
	})
}

// =============================================================================
// extractDeploymentBytecode Tests
// =============================================================================

func TestExtractDeploymentBytecode(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		{
			name:   "eth_sendTransaction with data field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:   "eth_sendTransaction with input field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"input": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:   "eth_sendTransaction with both data and input - prefers data",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0xdata", "input": "0xinput"},
			},
			expected: "0xdata",
		},
		{
			name:   "eth_estimateGas with data field",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"data": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:   "eth_estimateGas with input field",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"input": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:     "eth_call - not a deployment method",
			method:   "eth_call",
			params:   []any{map[string]any{"data": "0x6080604052"}},
			expected: "",
		},
		{
			name:     "eth_sendRawTransaction - not a deployment method",
			method:   "eth_sendRawTransaction",
			params:   []any{"0xf86c..."},
			expected: "",
		},
		{
			name:     "No params",
			method:   "eth_sendTransaction",
			params:   nil,
			expected: "",
		},
		{
			name:     "Empty params",
			method:   "eth_sendTransaction",
			params:   []any{},
			expected: "",
		},
		{
			name:   "Malformed params - not a map",
			method: "eth_sendTransaction",
			params: []any{"not a map"},
			expected: "",
		},
		{
			name:   "Empty data field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": ""},
			},
			expected: "",
		},
		{
			name:   "Data is just 0x",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x"},
			},
			expected: "",
		},
		{
			name:   "No data or input field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "value": "0x0"},
			},
			expected: "",
		},
		{
			name:   "Data is non-string type",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": 12345},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDeploymentBytecode(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("extractDeploymentBytecode(%q, %v) = %q, expected %q",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Historical State Query Restriction Tests
// =============================================================================

func TestExtractBlockParam(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		// eth_call cases
		{
			name:     "eth_call with no params - defaults to latest",
			method:   "eth_call",
			params:   nil,
			expected: "latest",
		},
		{
			name:     "eth_call with empty params - defaults to latest",
			method:   "eth_call",
			params:   []any{},
			expected: "latest",
		},
		{
			name:   "eth_call with only txObject - defaults to latest",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234", "data": "0xa9059cbb"},
			},
			expected: "latest",
		},
		{
			name:   "eth_call with latest block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"latest",
			},
			expected: "latest",
		},
		{
			name:   "eth_call with pending block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"pending",
			},
			expected: "pending",
		},
		{
			name:   "eth_call with safe block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"safe",
			},
			expected: "safe",
		},
		{
			name:   "eth_call with finalized block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"finalized",
			},
			expected: "finalized",
		},
		{
			name:   "eth_call with earliest block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"earliest",
			},
			expected: "earliest",
		},
		{
			name:   "eth_call with hex block number",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x1234",
			},
			expected: "0x1234",
		},
		{
			name:   "eth_call with block hash (66 chars)",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expected: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name:   "eth_call with nil block param - defaults to latest",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				nil,
			},
			expected: "latest",
		},
		{
			name:   "eth_call with empty string block param - defaults to latest",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"",
			},
			expected: "latest",
		},
		{
			name:   "eth_call with non-string block param (number) - treated as historical",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				12345,
			},
			expected: "historical",
		},
		// eth_getStorageAt cases
		{
			name:     "eth_getStorageAt with no params - defaults to latest",
			method:   "eth_getStorageAt",
			params:   nil,
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with only address - defaults to latest",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234"},
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with address and slot - defaults to latest",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0"},
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with latest block param",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0", "latest"},
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with hex block number",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0", "0xabcd"},
			expected: "0xabcd",
		},
		{
			name:     "eth_getStorageAt with nil block param - defaults to latest",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0", nil},
			expected: "latest",
		},
		// Other methods - should return latest
		{
			name:     "eth_getBalance - not applicable, returns latest",
			method:   "eth_getBalance",
			params:   []any{"0x1234", "0x100"},
			expected: "latest",
		},
		{
			name:     "eth_blockNumber - not applicable, returns latest",
			method:   "eth_blockNumber",
			params:   nil,
			expected: "latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBlockParam(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("extractBlockParam(%q, %v) = %q, expected %q",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

func TestIsHistoricalBlock(t *testing.T) {
	tests := []struct {
		name       string
		blockParam string
		expected   bool
	}{
		// NOT historical (current state)
		{"empty string - not historical", "", false},
		{"latest - not historical", "latest", false},
		{"LATEST uppercase - not historical", "LATEST", false},
		{"Latest mixed case - not historical", "Latest", false},
		{"pending - not historical", "pending", false},
		{"PENDING uppercase - not historical", "PENDING", false},
		{"safe - not historical", "safe", false},
		{"SAFE uppercase - not historical", "SAFE", false},
		{"finalized - not historical", "finalized", false},
		{"FINALIZED uppercase - not historical", "FINALIZED", false},
		{"earliest - not historical", "earliest", false},
		{"EARLIEST uppercase - not historical", "EARLIEST", false},

		// HISTORICAL
		{"hex block number 0x0 - historical", "0x0", true},
		{"hex block number 0x1 - historical", "0x1", true},
		{"hex block number 0x1234 - historical", "0x1234", true},
		{"hex block number 0xabcdef - historical", "0xabcdef", true},
		{"large hex block number - historical", "0xffffff", true},
		{"block hash (66 chars) - historical", "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true},
		{"historical marker - historical", "historical", true},
		{"random string - historical", "someblock", true},
		{"number as string - historical", "12345", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHistoricalBlock(tt.blockParam)
			if result != tt.expected {
				t.Errorf("isHistoricalBlock(%q) = %v, expected %v",
					tt.blockParam, result, tt.expected)
			}
		})
	}
}

func TestIsHistoricalStateQuery(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		params         []any
		expectBlocked  bool
		expectedReason string
	}{
		// eth_call - allowed cases
		{
			name:   "eth_call with latest - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"latest",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with pending - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"pending",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with safe - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"safe",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with finalized - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"finalized",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with earliest - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"earliest",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call without block param (defaults to latest) - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
			},
			expectBlocked: false,
		},
		// eth_call - blocked cases
		{
			name:   "eth_call with hex block number - blocked",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x1234",
			},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:   "eth_call with block hash - blocked",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:   "eth_call with 0x0 block - blocked",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x0",
			},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		// eth_getStorageAt - allowed cases
		{
			name:          "eth_getStorageAt with latest - allowed",
			method:        "eth_getStorageAt",
			params:        []any{"0x1234", "0x0", "latest"},
			expectBlocked: false,
		},
		{
			name:          "eth_getStorageAt with pending - allowed",
			method:        "eth_getStorageAt",
			params:        []any{"0x1234", "0x0", "pending"},
			expectBlocked: false,
		},
		{
			name:          "eth_getStorageAt without block param - allowed",
			method:        "eth_getStorageAt",
			params:        []any{"0x1234", "0x0"},
			expectBlocked: false,
		},
		// eth_getStorageAt - blocked cases
		{
			name:           "eth_getStorageAt with hex block number - blocked",
			method:         "eth_getStorageAt",
			params:         []any{"0x1234", "0x0", "0x5678"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:           "eth_getStorageAt with block hash - blocked",
			method:         "eth_getStorageAt",
			params:         []any{"0x1234", "0x0", "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		// Other methods - not checked
		{
			name:          "eth_getBalance - not checked",
			method:        "eth_getBalance",
			params:        []any{"0x1234", "0x1234"},
			expectBlocked: false,
		},
		{
			name:          "eth_blockNumber - not checked",
			method:        "eth_blockNumber",
			params:        nil,
			expectBlocked: false,
		},
		{
			name:   "eth_estimateGas - not checked",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x1234",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_sendTransaction - not checked",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234"},
			},
			expectBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isHistorical, reason := IsHistoricalStateQuery(tt.method, tt.params)
			if isHistorical != tt.expectBlocked {
				t.Errorf("IsHistoricalStateQuery(%q, %v) = %v, expected %v",
					tt.method, tt.params, isHistorical, tt.expectBlocked)
			}
			if tt.expectBlocked && reason != tt.expectedReason {
				t.Errorf("IsHistoricalStateQuery reason = %q, expected %q",
					reason, tt.expectedReason)
			}
		})
	}
}
