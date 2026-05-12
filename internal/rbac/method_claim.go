package rbac

import (
	"sort"
	"strings"
)

// ReadMethods classifies read-only RPC methods.
// These methods only read blockchain state and don't modify it.
// Note: No longer used for claim gating — retained for AllAllowedMethods() and reference.
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

// WriteMethods classifies state-modifying RPC methods.
// Note: No longer used for claim gating — retained for AllAllowedMethods() and reference.
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
// Returns an empty string for read/write methods (gated by method allowlist, not claims).
// Only deploy-tier methods (debug_trace*) return a non-empty claim.
func GetClaimForMethod(method string) Claim {
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
// Only deploy-tier methods (debug_trace*) require a claim; read/write
// methods are gated by the method allowlist alone.
func ValidateMethodsMatchClaims(methods []string, claims []Claim) error {
	// Build a set of available claims
	hasClaim := make(map[Claim]bool)
	for _, c := range claims {
		hasClaim[c] = true
	}

	// Check each method — only deploy methods need a claim
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

// ExtraMethods holds operator-configured explicit chain-specific methods (e.g. linea_*).
// Populated at startup via RegisterExtraNamespaces from the explicit list only —
// wildcard-matched methods are open-ended and not enumerated here.
var ExtraMethods = map[string]bool{}

// ExtraNamespaces holds the structured namespace→explicit method names mapping
// from config. Used by the status API to expose available methods to the frontend.
var ExtraNamespaces map[string][]string

// MethodAliases maps chain-specific methods to their standard equivalents
// for access control purposes (e.g. "linea_estimateGas" → "eth_estimateGas").
// Methods with aliases inherit the same contract access checks, storage slot
// tiering, deployment detection, and function selector extraction as their target.
//
// Wildcard-matched methods do NOT populate this map — they pass through to the
// upstream node without alias-based redaction (see WildcardNamespace).
var MethodAliases = map[string]string{}

// WildcardNamespace describes a chain namespace that opts into prefix-wildcard
// passthrough. Methods that start with Prefix and don't match any Deny glob are
// allowed to pass through to the upstream node verbatim — no contract access
// check, no field-level redaction. Operators take responsibility for what may
// appear under the prefix; safety floor is GlobalBlockedMethods + Deny.
type WildcardNamespace struct {
	Namespace string   // human-readable namespace name, e.g. "Linea"
	Prefix    string   // method-name prefix, e.g. "linea_"
	Deny      []string // glob patterns: "linea_sendTransaction", "linea_sign*"
}

// Wildcards lists all namespaces that have wildcard mode enabled. Populated at
// startup via RegisterExtraNamespaces. Iteration order is deterministic for
// reproducible audit logs.
var Wildcards []*WildcardNamespace

// RegisterExtraNamespaces registers operator-configured chain-specific methods,
// their access control aliases, and any prefix-wildcard configurations. Called
// once at startup from server initialization. The wildcards parameter may be
// nil for v1 configs that don't use wildcard mode.
func RegisterExtraNamespaces(methodNames map[string][]string, aliases map[string]string, wildcards []*WildcardNamespace) {
	ExtraNamespaces = methodNames
	for _, methods := range methodNames {
		for _, m := range methods {
			ExtraMethods[m] = true
		}
	}
	for method, alias := range aliases {
		MethodAliases[method] = alias
	}
	Wildcards = wildcards
}

// ResolveMethodAlias returns the standard method name that a chain-specific method
// should be treated as for access control. Returns the method itself if no alias
// is registered (which is the case for wildcard-matched methods — they pass
// through without alias inheritance).
func ResolveMethodAlias(method string) string {
	if alias, ok := MethodAliases[method]; ok {
		return alias
	}
	return method
}

// MatchWildcard returns the WildcardNamespace that allows the given method,
// or nil if no wildcard covers it (or a deny glob matches first). The check
// is case-sensitive — method names are normalized upstream of this call.
func MatchWildcard(method string) *WildcardNamespace {
	for _, w := range Wildcards {
		if !strings.HasPrefix(method, w.Prefix) {
			continue
		}
		if matchAnyDenyGlob(method, w.Deny) {
			// Deny wins even when prefix matches; do not fall through to
			// other wildcards (they would only match if their prefix is a
			// subset, which is operator misconfiguration).
			return nil
		}
		return w
	}
	return nil
}

// matchAnyDenyGlob reports whether method matches any of the deny patterns.
// Patterns support a single trailing '*' wildcard; otherwise exact match.
func matchAnyDenyGlob(method string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(method, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if method == p {
			return true
		}
	}
	return false
}

// HasWildcardForPrefix reports whether a wildcard namespace is registered with
// exactly the given prefix. Used by GroupAccess.HasMethod to validate that a
// "prefix*" glob entry in a group's allowed_methods binds to a real wildcard
// (groups can't invent prefixes the operator hasn't enabled globally).
func HasWildcardForPrefix(prefix string) bool {
	for _, w := range Wildcards {
		if w.Prefix == prefix {
			return true
		}
	}
	return false
}

// IsDeniedByWildcard reports whether the method is explicitly denied by any
// registered wildcard namespace's Deny list. Used by HasMethod as a hard
// floor that runs BEFORE the explicit-allow short-circuit (security audit
// M8): pre-fix a tier-1/2 admin could enumerate `linea_sendTransaction`
// in a group's allowed_methods and bypass a Wildcard{Prefix:"linea_",
// Deny:["linea_sendTransaction"]} configured by the operator.
//
// Returns true only when a wildcard covers the method's prefix AND the
// Deny list rejects this specific method.
func IsDeniedByWildcard(method string) bool {
	for _, w := range Wildcards {
		if !strings.HasPrefix(method, w.Prefix) {
			continue
		}
		if matchAnyDenyGlob(method, w.Deny) {
			return true
		}
		// Wildcard covers the prefix but doesn't deny — keep iterating
		// in case a more specific wildcard with deny also applies (the
		// usual case is a single wildcard per prefix).
	}
	return false
}

// AllAllowedMethods returns every RPC method that can legitimately appear in a
// group's allowed_methods list. This is the union of ReadMethods, WriteMethods,
// DeployMethods, and ExtraMethods, minus any method that is globally blocked.
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
	for method := range ExtraMethods {
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
