package rbac

import "sort"

// ReadMethods are RPC methods that require the "read" claim.
// These methods only read blockchain state and don't modify it.
var ReadMethods = map[string]bool{
	// Chain/Network info
	"eth_chainId":      true,
	"eth_blockNumber":  true,
	"net_version":      true,
	"net_listening":    true,
	"net_peerCount":    true,
	"web3_clientVersion": true,
	"web3_sha3":        true,
	"eth_syncing":      true,
	"eth_accounts":     true,

	// Account/Balance queries
	"eth_getBalance":           true,
	"eth_getCode":              true,
	"eth_getStorageAt":         true,
	"eth_getTransactionCount":  true,

	// Block queries
	"eth_getBlockByHash":                     true,
	"eth_getBlockByNumber":                   true,
	"eth_getBlockTransactionCountByHash":     true,
	"eth_getBlockTransactionCountByNumber":   true,

	// Transaction queries
	"eth_getTransactionByHash":              true,
	"eth_getTransactionReceipt":             true,
	"eth_getTransactionByBlockHashAndIndex": true,
	"eth_getTransactionByBlockNumberAndIndex": true,

	// Contract calls (read-only)
	"eth_call":        true,
	"eth_estimateGas": true,

	// Gas price queries
	"eth_gasPrice":             true,
	"eth_maxPriorityFeePerGas": true,
	"eth_feeHistory":           true,

	// Logs
	"eth_getLogs": true,

	// Filter methods (used for event polling)
	"eth_newFilter":                  true,
	"eth_newBlockFilter":             true,
	"eth_newPendingTransactionFilter": true,
	"eth_getFilterChanges":           true,
	"eth_getFilterLogs":              true,
	"eth_uninstallFilter":            true,
}

// WriteMethods are RPC methods that require the "write" claim.
// These methods can modify blockchain state by sending transactions.
var WriteMethods = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
	"eth_sign":               true,
	"eth_signTransaction":    true,
	"personal_sign":          true,
	"eth_signTypedData":      true,
	"eth_signTypedData_v4":   true,
}

// DeployMethods are highly privileged RPC methods that require the "deploy" or "admin" claim.
// Checked dynamically by trace validators for cross-org data leaks.
var DeployMethods = map[string]bool{
	"debug_traceTransaction": true,
	"debug_traceCall":        true,
}

// GetClaimForMethod returns the claim required for a given RPC method.
// Returns an empty string if the method doesn't require a specific claim
// (either it's a general method or it's blocked by the global blocklist).
func GetClaimForMethod(method string) Claim {
	if ReadMethods[method] {
		return ClaimRead
	}
	if WriteMethods[method] {
		return ClaimWrite
	}
	if DeployMethods[method] {
		return ClaimDeploy
	}
	return ""
}

// IsReadMethod returns true if the method requires the "read" claim.
func IsReadMethod(method string) bool {
	return ReadMethods[method]
}

// IsWriteMethod returns true if the method requires the "write" claim.
func IsWriteMethod(method string) bool {
	return WriteMethods[method]
}

// ValidateMethodsMatchClaims checks that all provided methods have
// their required claims in the claims list.
// Returns an error if any method requires a claim that's not present.
func ValidateMethodsMatchClaims(methods []string, claims []Claim) error {
	// Build a set of available claims
	hasClaim := make(map[Claim]bool)
	for _, c := range claims {
		hasClaim[c] = true
	}

	// Check each method
	for _, method := range methods {
		requiredClaim := GetClaimForMethod(method)
		if requiredClaim != "" && !hasClaim[requiredClaim] {
			return &MethodClaimMismatchError{
				Method:        method,
				RequiredClaim: requiredClaim,
			}
		}
	}

	return nil
}

// MethodClaimMismatchError is returned when a method requires a claim
// that is not present in the claims list.
type MethodClaimMismatchError struct {
	Method        string
	RequiredClaim Claim
}

func (e *MethodClaimMismatchError) Error() string {
	return "method " + e.Method + " requires " + string(e.RequiredClaim) + " claim"
}

// GetAllReadMethods returns a slice of all read method names.
func GetAllReadMethods() []string {
	methods := make([]string, 0, len(ReadMethods))
	for method := range ReadMethods {
		methods = append(methods, method)
	}
	return methods
}

// GetAllWriteMethods returns a slice of all write method names.
func GetAllWriteMethods() []string {
	methods := make([]string, 0, len(WriteMethods))
	for method := range WriteMethods {
		methods = append(methods, method)
	}
	return methods
}

// GetAllDeployMethods returns a slice of all deploy method names.
func GetAllDeployMethods() []string {
	methods := make([]string, 0, len(DeployMethods))
	for method := range DeployMethods {
		methods = append(methods, method)
	}
	return methods
}

// AllAllowedMethods returns every RPC method that can legitimately appear in a
// group's allowed_methods list. This is the union of ReadMethods, WriteMethods,
// and DeployMethods, minus any method that is globally blocked.
// Used to expand a wildcard "*" into an explicit method list.
func AllAllowedMethods() []string {
	seen := make(map[string]bool)
	var methods []string

	for method := range ReadMethods {
		if !IsMethodBlocked(method) && !seen[method] {
			seen[method] = true
			methods = append(methods, method)
		}
	}
	for method := range WriteMethods {
		if !IsMethodBlocked(method) && !seen[method] {
			seen[method] = true
			methods = append(methods, method)
		}
	}
	for method := range DeployMethods {
		if !IsMethodBlocked(method) && !seen[method] {
			seen[method] = true
			methods = append(methods, method)
		}
	}

	// Sort for deterministic output
	sort.Strings(methods)
	return methods
}

// ExpandWildcardMethods replaces a wildcard "*" entry in the given method list
// with the full explicit set from AllAllowedMethods(). If no wildcard is present,
// the input is returned unchanged.
func ExpandWildcardMethods(methods []string) []string {
	for _, m := range methods {
		if m == "*" {
			return AllAllowedMethods()
		}
	}
	return methods
}
