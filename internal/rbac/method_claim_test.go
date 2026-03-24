package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClaimForMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   Claim
	}{
		// Read methods
		{name: "eth_call is read", method: "eth_call", want: ClaimRead},
		{name: "eth_getBalance is read", method: "eth_getBalance", want: ClaimRead},
		{name: "eth_chainId is read", method: "eth_chainId", want: ClaimRead},
		{name: "eth_blockNumber is read", method: "eth_blockNumber", want: ClaimRead},
		{name: "eth_estimateGas is read", method: "eth_estimateGas", want: ClaimRead},
		{name: "eth_getLogs is read", method: "eth_getLogs", want: ClaimRead},
		{name: "eth_getTransactionReceipt is read", method: "eth_getTransactionReceipt", want: ClaimRead},
		{name: "eth_getCode is read", method: "eth_getCode", want: ClaimRead},
		{name: "net_version is read", method: "net_version", want: ClaimRead},
		{name: "web3_clientVersion is read", method: "web3_clientVersion", want: ClaimRead},
		{name: "eth_newFilter is read", method: "eth_newFilter", want: ClaimRead},
		{name: "eth_getFilterChanges is read", method: "eth_getFilterChanges", want: ClaimRead},

		// Write methods
		{name: "eth_sendTransaction is write", method: "eth_sendTransaction", want: ClaimWrite},
		{name: "eth_sendRawTransaction is write", method: "eth_sendRawTransaction", want: ClaimWrite},
		{name: "eth_sign is write", method: "eth_sign", want: ClaimWrite},
		{name: "eth_signTransaction is write", method: "eth_signTransaction", want: ClaimWrite},
		{name: "personal_sign is write", method: "personal_sign", want: ClaimWrite},
		{name: "eth_signTypedData is write", method: "eth_signTypedData", want: ClaimWrite},
		{name: "eth_signTypedData_v4 is write", method: "eth_signTypedData_v4", want: ClaimWrite},

		// Unknown/uncategorized methods
		{name: "unknown method returns empty", method: "unknown_method", want: ""},
		{name: "debug method returns deploy", method: "debug_traceCall", want: ClaimDeploy},
		{name: "admin method returns empty", method: "admin_peers", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetClaimForMethod(tt.method)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsReadMethod(t *testing.T) {
	assert.True(t, IsReadMethod("eth_call"))
	assert.True(t, IsReadMethod("eth_getBalance"))
	assert.True(t, IsReadMethod("eth_chainId"))
	assert.False(t, IsReadMethod("eth_sendTransaction"))
	assert.False(t, IsReadMethod("unknown_method"))
}

func TestIsWriteMethod(t *testing.T) {
	assert.True(t, IsWriteMethod("eth_sendTransaction"))
	assert.True(t, IsWriteMethod("eth_sendRawTransaction"))
	assert.True(t, IsWriteMethod("eth_sign"))
	assert.False(t, IsWriteMethod("eth_call"))
	assert.False(t, IsWriteMethod("unknown_method"))
}

func TestValidateMethodsMatchClaims(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		claims  []Claim
		wantErr bool
		errMsg  string
	}{
		{
			name:    "read methods with read claim",
			methods: []string{"eth_call", "eth_getBalance", "eth_chainId"},
			claims:  []Claim{ClaimRead},
			wantErr: false,
		},
		{
			name:    "write methods with write claim",
			methods: []string{"eth_sendTransaction", "eth_sendRawTransaction"},
			claims:  []Claim{ClaimWrite},
			wantErr: false,
		},
		{
			name:    "mixed methods with both claims",
			methods: []string{"eth_call", "eth_sendTransaction", "eth_getBalance"},
			claims:  []Claim{ClaimRead, ClaimWrite},
			wantErr: false,
		},
		{
			name:    "read methods without read claim",
			methods: []string{"eth_call"},
			claims:  []Claim{ClaimWrite},
			wantErr: true,
			errMsg:  "method eth_call requires read claim",
		},
		{
			name:    "write methods without write claim",
			methods: []string{"eth_sendTransaction"},
			claims:  []Claim{ClaimRead},
			wantErr: true,
			errMsg:  "method eth_sendTransaction requires write claim",
		},
		{
			name:    "mixed methods missing write claim",
			methods: []string{"eth_call", "eth_sendTransaction"},
			claims:  []Claim{ClaimRead},
			wantErr: true,
			errMsg:  "method eth_sendTransaction requires write claim",
		},
		{
			name:    "empty methods list",
			methods: []string{},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "unknown methods don't require claims",
			methods: []string{"some_unknown_method"},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "all claims provided",
			methods: []string{"eth_call", "eth_sendTransaction"},
			claims:  []Claim{ClaimRead, ClaimWrite, ClaimAdmin, ClaimUpgrade, ClaimDeploy},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMethodsMatchClaims(tt.methods, tt.claims)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Equal(t, tt.errMsg, err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMethodClaimMismatchError(t *testing.T) {
	err := &MethodClaimMismatchError{
		Method:        "eth_sendTransaction",
		RequiredClaim: ClaimWrite,
	}
	assert.Equal(t, "method eth_sendTransaction requires write claim", err.Error())
}

func TestGetAllReadMethods(t *testing.T) {
	methods := GetAllReadMethods()
	assert.NotEmpty(t, methods)

	// Check that all returned methods are actually read methods
	for _, m := range methods {
		assert.True(t, IsReadMethod(m), "method %s should be a read method", m)
	}

	// Check that the count matches the map
	assert.Equal(t, len(ReadMethods), len(methods))
}

func TestGetAllWriteMethods(t *testing.T) {
	methods := GetAllWriteMethods()
	assert.NotEmpty(t, methods)

	// Check that all returned methods are actually write methods
	for _, m := range methods {
		assert.True(t, IsWriteMethod(m), "method %s should be a write method", m)
	}

	// Check that the count matches the map
	assert.Equal(t, len(WriteMethods), len(methods))
}
