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
