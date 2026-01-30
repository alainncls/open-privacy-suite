package rbac

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"privacy-proxy/internal/evm/bytecode"

	"github.com/google/uuid"
)

// GlobalBlockedMethods contains methods that are NEVER allowed regardless of RBAC permissions.
// These methods pose security risks and should never be exposed through the proxy.
// Using map for O(1) lookup instead of slice.
var GlobalBlockedMethods = map[string]bool{
	// Debug namespace - information disclosure, DoS risk
	"debug_accountRange":                true,
	"debug_backtraceAt":                 true,
	"debug_blockProfile":                true,
	"debug_chaindbCompact":              true,
	"debug_chaindbProperty":             true,
	"debug_cpuProfile":                  true,
	"debug_dbAncient":                   true,
	"debug_dbAncients":                  true,
	"debug_dbGet":                       true,
	"debug_dumpBlock":                   true,
	"debug_freeOSMemory":                true,
	"debug_freezeClient":                true,
	"debug_gcStats":                     true,
	"debug_getBadBlocks":                true,
	"debug_getHeaderRlp":                true,
	"debug_getModifiedAccountsByHash":   true,
	"debug_getModifiedAccountsByNumber": true,
	"debug_goTrace":                     true,
	"debug_intermediateRoots":           true,
	"debug_memStats":                    true,
	"debug_mutexProfile":                true,
	"debug_preimage":                    true,
	"debug_printBlock":                  true,
	"debug_seedHash":                    true,
	"debug_setBlockProfileRate":         true,
	"debug_setGCPercent":                true,
	"debug_setHead":                     true,
	"debug_setMutexProfileFraction":     true,
	"debug_stacks":                      true,
	"debug_standardTraceBadBlockToFile": true,
	"debug_standardTraceBlockToFile":    true,
	"debug_startCPUProfile":             true,
	"debug_startGoTrace":                true,
	"debug_stopCPUProfile":              true,
	"debug_stopGoTrace":                 true,
	"debug_storageRangeAt":              true,
	"debug_subscribe":                   true,
	"debug_traceBadBlock":               true,
	"debug_traceBlock":                  true,
	"debug_traceBlockByHash":            true,
	"debug_traceBlockByNumber":          true,
	"debug_traceBlockFromFile":          true,
	"debug_traceCall":                   true,
	"debug_traceChain":                  true,
	"debug_traceTransaction":            true,
	"debug_unsubscribe":                 true,
	"debug_verbosity":                   true,
	"debug_vmodule":                     true,
	"debug_writeBlockProfile":           true,
	"debug_writeMemProfile":             true,
	"debug_writeMutexProfile":           true,

	// Admin namespace - node administration
	"admin_addPeer":           true,
	"admin_addTrustedPeer":    true,
	"admin_clearHistory":      true,
	"admin_datadir":           true,
	"admin_exportChain":       true,
	"admin_importChain":       true,
	"admin_nodeInfo":          true,
	"admin_peers":             true,
	"admin_removePeer":        true,
	"admin_removeTrustedPeer": true,
	"admin_sleep":             true,
	"admin_sleepBlocks":       true,
	"admin_startHTTP":         true,
	"admin_startRPC":          true,
	"admin_startWS":           true,
	"admin_stopHTTP":          true,
	"admin_stopRPC":           true,
	"admin_stopWS":            true,

	// Personal namespace - key exposure risk
	"personal_deriveAccount":    true,
	"personal_ecRecover":        true,
	"personal_importRawKey":     true,
	"personal_initializeWallet": true,
	"personal_listAccounts":     true,
	"personal_listWallets":      true,
	"personal_lockAccount":      true,
	"personal_newAccount":       true,
	"personal_openWallet":       true,
	"personal_sendTransaction":  true,
	"personal_sign":             true,
	"personal_signTransaction":  true,
	"personal_unlockAccount":    true,
	"personal_unpair":           true,

	// Miner namespace - MEV risk, node control
	"miner_getHashrate":         true,
	"miner_setEtherbase":        true,
	"miner_setExtra":            true,
	"miner_setGasLimit":         true,
	"miner_setGasPrice":         true,
	"miner_setRecommitInterval": true,
	"miner_start":               true,
	"miner_stop":                true,

	// Txpool namespace - MEV risk, information disclosure
	"txpool_content":     true,
	"txpool_contentFrom": true,
	"txpool_inspect":     true,
	"txpool_status":      true,

	// Signing methods - key exposure risk
	"eth_sign":            true,
	"eth_signTransaction": true,

	// Raw transaction - bypasses all RBAC validation (no RLP decoding)
	// Attackers could deploy contracts to any address, bypass bytecode validation,
	// and circumvent cross-org isolation. Use eth_sendTransaction instead.
	"eth_sendRawTransaction": true,

	// Clique namespace - consensus manipulation
	"clique_discard":           true,
	"clique_getSigners":        true,
	"clique_getSignersAtHash":  true,
	"clique_getSnapshot":       true,
	"clique_getSnapshotAtHash": true,
	"clique_proposals":         true,
	"clique_propose":           true,
	"clique_status":            true,

	// Les namespace - light client control
	"les_addBalance":         true,
	"les_clientInfo":         true,
	"les_latestCheckpoint":   true,
	"les_priorityClientInfo": true,
	"les_serverInfo":         true,
	"les_setClientParams":    true,
	"les_setDefaultParams":   true,

	// WebSocket subscriptions - not supported, use polling instead
	// eth_subscribe could bypass eth_getLogs filtering for real-time events
	"eth_subscribe":   true,
	"eth_unsubscribe": true,
}

// blockedMethodPrefixes is used for future-proofing (checked after exact match fails)
var blockedMethodPrefixes = []string{
	"debug_",
	"admin_",
	"personal_",
	"miner_",
	"txpool_",
	"clique_",
	"les_",
}

// IsMethodBlocked checks if a method is globally blocked.
func IsMethodBlocked(method string) bool {
	// Check exact match in map (O(1) lookup)
	if GlobalBlockedMethods[method] {
		return true
	}

	// Check prefix matches for future-proofing
	for _, prefix := range blockedMethodPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}

	return false
}

// Multicall contract addresses (Multicall3 is deployed at same address on most chains)
var MulticallAddresses = map[string]bool{
	"0xca11bde05977b3631167028862be2a173976ca11": true, // Multicall3
	"0x5ba1e12693dc8f9c48aad8770482f4739beed696": true, // Multicall2 (Ethereum mainnet)
	"0xeefba1e63905ef1d7acba5a8513c70307c1ce441": true, // Multicall (original)
}

// Multicall function selectors (first 4 bytes of keccak256 hash)
var MulticallSelectors = map[string]string{
	"0x252dba42": "aggregate",            // aggregate((address,bytes)[])
	"0x82ad56cb": "aggregate3",           // aggregate3((address,bool,bytes)[])
	"0x174dea71": "aggregate3Value",      // aggregate3Value((address,bool,uint256,bytes)[])
	"0xc3077fa9": "blockAndAggregate",    // blockAndAggregate((address,bytes)[])
	"0xbce38bd7": "tryAggregate",         // tryAggregate(bool,(address,bytes)[])
	"0x399542e9": "tryBlockAndAggregate", // tryBlockAndAggregate(bool,(address,bytes)[])
}

// IsMulticallTarget checks if the target address is a known Multicall contract.
func IsMulticallTarget(address string) bool {
	return MulticallAddresses[strings.ToLower(address)]
}

// IsMulticallData checks if the call data appears to be a Multicall function call.
// Returns true if the data starts with a known Multicall function selector.
func IsMulticallData(data string) bool {
	if len(data) < 10 { // "0x" + 8 hex chars for selector
		return false
	}
	selector := strings.ToLower(data[:10])
	_, isMulticall := MulticallSelectors[selector]
	return isMulticall
}

// DetectMulticall checks if a request is a Multicall that could bypass contract ACLs.
// Returns (isMulticall, reason) where reason explains why Multicall was detected.
// Blocks eth_call, eth_estimateGas, AND eth_sendTransaction to Multicall contracts
// because inner calls cannot be validated against per-contract ACLs.
func DetectMulticall(method string, params []any) (bool, string) {
	// Check all methods that can interact with Multicall contracts
	// - eth_call: read batching (information disclosure risk)
	// - eth_estimateGas: gas estimation for batched operations
	// - eth_sendTransaction: write batching (state manipulation risk - most severe)
	if method != "eth_call" && method != "eth_estimateGas" && method != "eth_sendTransaction" {
		return false, ""
	}

	if len(params) == 0 {
		return false, ""
	}

	callObj, ok := params[0].(map[string]any)
	if !ok {
		return false, ""
	}

	to, ok := callObj["to"].(string)
	if !ok || to == "" {
		return false, ""
	}

	// Check if targeting a Multicall contract
	if !IsMulticallTarget(to) {
		return false, ""
	}

	// Check if the data is a Multicall function
	data, ok := callObj["data"].(string)
	if !ok || data == "" {
		return false, ""
	}

	if IsMulticallData(data) {
		return true, fmt.Sprintf("multicall to %s detected - inner calls cannot be validated", to)
	}

	return false, ""
}

// AccessController handles access control decisions for RBAC.
type AccessController struct {
	store                Store
	resolver             *Resolver
	cache                *Cache
	deployValidator      *DeploymentValidator
	upgradeValidator     *UpgradeValidator
	factoryCallValidator *FactoryCallValidator
	pendingTracker       *PendingDeploymentTracker
}

// Store returns the underlying RBAC store for the access controller.
// This is used for cross-org isolation checks that require direct database access.
func (c *AccessController) Store() Store {
	return c.store
}

// NewAccessController creates a new access controller.
func NewAccessController(store Store, cacheTTL time.Duration) *AccessController {
	deployValidator := NewDeploymentValidator(store)
	return &AccessController{
		store:                store,
		resolver:             NewResolver(store, cacheTTL),
		cache:                NewCache(CacheConfig{TTL: cacheTTL}),
		deployValidator:      deployValidator,
		upgradeValidator:     NewUpgradeValidator(store),
		factoryCallValidator: NewFactoryCallValidator(store, deployValidator),
		pendingTracker:       NewPendingDeploymentTracker(1 * time.Hour),
	}
}

// CheckAccess validates if a request should be allowed based on RBAC.
func (c *AccessController) CheckAccess(ctx context.Context, req *AccessCheckRequest) (*AccessCheckResult, error) {
	// Check global blocklist FIRST - before any RBAC evaluation
	if IsMethodBlocked(req.Method) {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("method %s is globally blocked for security reasons", req.Method),
		}, nil
	}

	// Check for Multicall bypass attempts
	if isMulticall, reason := DetectMulticall(req.Method, req.Params); isMulticall {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  reason,
		}, nil
	}

	// Check for historical state queries (privacy protection)
	if isHistorical, reason := IsHistoricalStateQuery(req.Method, req.Params); isHistorical {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  reason,
		}, nil
	}

	// Get user by external ID
	user, err := c.store.GetUserByExternalID(ctx, req.UserExternalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// If user doesn't exist in RBAC, deny access
	if user == nil {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("user not found: %s", req.UserExternalID),
		}, nil
	}


	// Check if user is banned
	if user.Banned {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  "user is banned",
		}, nil
	}

	// Check KYC requirement
	if !user.KYC {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  "KYC verification required",
		}, nil
	}

	// Determine organization
	// Default to "default" org for single-tenant deployments or when org not specified.
	// The default org is seeded in migrations and provides baseline permissions.
	orgSlug := req.OrgSlug
	if orgSlug == "" {
		orgSlug = "default"
	}

	org, err := c.store.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	if org == nil {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("organization not found: %s", orgSlug),
		}, nil
	}

	// Check in-memory cache first
	cachedPerms := c.cache.Get(user.ID, org.ID)

	var perms *EffectivePermissions
	if cachedPerms != nil {
		perms = cachedPerms
	} else {
		// Resolve permissions (checks DB cache, then computes)
		perms, err = c.resolver.ResolvePermissions(ctx, user.ID, org.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve permissions: %w", err)
		}

		// Store in in-memory cache
		c.cache.Set(perms)
	}

	// Check method permission
	if !perms.HasMethod(req.Method) {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("method %s not allowed", req.Method),
		}, nil
	}

	// Handle eth_getLogs specially - needs multi-address validation
	// eth_getLogs can have multiple addresses in the filter, unlike other methods
	// that target a single contract. We validate ALL addresses in the filter.
	if req.Method == "eth_getLogs" {
		if err := c.validateGetLogsAccessWithCrossOrgCheck(ctx, perms, req.Params); err != nil {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  err.Error(),
			}, nil
		}
		// eth_getLogs passed validation - return allowed with rate limits
		allClaims := collectAllClaims(perms)
		return &AccessCheckResult{
			Allowed:        true,
			RateLimitRPS:   perms.RateLimitRPS,
			RateLimitDaily: perms.RateLimitDaily,
			Claims:         allClaims,
		}, nil
	}

	// Determine required claim based on the operation
	requiredClaim := ClassifyOperation(req.Method, req.Params)

	// Check contract access if target address is specified
	if req.TargetAddress != "" {
		addr := strings.ToLower(req.TargetAddress)

		// Check if user has EXPLICIT access to this contract in their permissions
		hasExplicitAccess := perms.IsContractRegistered(addr)

		// Get contract access for this address (may return default_claims for unregistered contracts)
		access := perms.GetContractAccess(addr)

		// If no access to this contract (not registered and no default claims), deny
		if access == nil {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("no access to contract %s", req.TargetAddress),
			}, nil
		}

		// CROSS-ORG ISOLATION CHECK (P0 Security Fix)
		// If user doesn't have explicit access but got access via default_claims,
		// we must verify the contract isn't registered to a DIFFERENT organization.
		// This prevents users from using default_claims to access contracts belonging to other orgs.
		// Contracts owned by the user's org are allowed with default_claims.
		if !hasExplicitAccess && ReadOpsMap[req.Method] {
			// User is relying on default_claims - first check if contract is in user's org
			isOwnedByUserOrg, err := c.store.IsAddressOwnedByOrg(ctx, addr, org.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to check contract ownership: %w", err)
			}

			if !isOwnedByUserOrg {
				// Contract is not in user's org - check if it's registered to any org
				isRegisteredToAnyOrg, err := c.store.IsContractRegisteredToAnyOrg(ctx, addr)
				if err != nil {
					return nil, fmt.Errorf("failed to check contract registration: %w", err)
				}

				if isRegisteredToAnyOrg {
					// Contract belongs to another organization - deny access
					return &AccessCheckResult{
						Allowed: false,
						Reason:  fmt.Sprintf("contract %s is registered to another organization", req.TargetAddress),
					}, nil
				}
			}
			// Contract is in user's org OR truly public (not registered to any org) - allow with default_claims
		}

		// Check if user has the required claim on this contract
		if requiredClaim != "" && !containsClaim(access.Claims, requiredClaim) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("missing %s claim on contract %s", requiredClaim, req.TargetAddress),
			}, nil
		}

		// Check function selector if specified
		if req.FunctionSelector != "" {
			if !perms.HasFunctionSelector(addr, req.FunctionSelector) {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  fmt.Sprintf("function %s not allowed on contract %s", req.FunctionSelector, req.TargetAddress),
				}, nil
			}
		}

		// Validate proxy upgrades for eth_sendTransaction (not deployments)
		// This must happen AFTER verifying write access
		if req.Method == "eth_sendTransaction" {
			calldata := extractCalldata(req.Method, req.Params)
			if len(calldata) > 0 {
				upgradeResult, err := c.upgradeValidator.ValidateUpgrade(ctx, org.ID, addr, calldata)
				if err != nil {
					return nil, fmt.Errorf("failed to validate upgrade: %w", err)
				}
				if !upgradeResult.Allowed {
					return &AccessCheckResult{
						Allowed: false,
						Reason:  fmt.Sprintf("proxy upgrade denied: %s", upgradeResult.Reason),
					}, nil
				}

				// Validate CREATE3 factory deploy() calls
				// This ensures deployments via factory go to preregistered addresses only
				factoryAddress := GetOrgFactoryAddress(org)
				if factoryAddress != "" {
					factoryResult, err := c.factoryCallValidator.ValidateFactoryCall(ctx, org.ID, factoryAddress, addr, calldata)
					if err != nil {
						return nil, fmt.Errorf("failed to validate factory call: %w", err)
					}
					if factoryResult.IsFactoryCall && factoryResult.IsDeployCall && !factoryResult.Allowed {
						return &AccessCheckResult{
							Allowed: false,
							Reason:  fmt.Sprintf("factory deploy denied: %s", factoryResult.Reason),
						}, nil
					}
				}
			}
		}
	} else if requiredClaim == ClaimDeploy {
		// No target address but operation requires 'deploy' claim (contract deployment)
		// Check if user has the deploy claim via default claims
		// Note: read/write claims without target_address are allowed without claim check
		// because contract-specific claims only apply when targeting a specific contract
		if !containsClaim(perms.DefaultClaims, ClaimDeploy) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  "missing required deploy claim for contract deployment",
			}, nil
		}

		// For contract deployments, validate the bytecode
		if requiredClaim == ClaimDeploy && IsContractDeployment(req.Method, req.Params) {
			bytecodeHex := extractDeploymentBytecode(req.Method, req.Params)
			if bytecodeHex == "" {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  "contract deployment missing bytecode",
				}, nil
			}

			validationResult, err := c.deployValidator.ValidateDeployment(ctx, org.ID, bytecodeHex)
			if err != nil {
				return nil, fmt.Errorf("failed to validate deployment bytecode: %w", err)
			}

			if !validationResult.Allowed {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  fmt.Sprintf("deployment validation failed: %s", validationResult.Reason),
				}, nil
			}

			// Factory contract deployment requires admin claim (security: prevent accidental factory proliferation)
			if validationResult.IsTrustedFactory {
				allClaims := collectAllClaims(perms)
				if !containsClaim(allClaims, ClaimAdmin) {
					return &AccessCheckResult{
						Allowed: false,
						Reason:  "CREATE3 factory deployment requires admin claim",
					}, nil
				}
			}

			// Include deployment info in the result for proxy tracking
			allClaims := collectAllClaims(perms)
			return &AccessCheckResult{
				Allowed:        true,
				RateLimitRPS:   perms.RateLimitRPS,
				RateLimitDaily: perms.RateLimitDaily,
				Claims:         allClaims,
				DeploymentInfo: &DeploymentInfo{
					OrgID:     org.ID,
					IsProxy:   validationResult.IsProxy,
					ProxyType: validationResult.ProxyType,
				},
			}, nil
		}
	}

	// Check additional required claims from the request
	for _, claim := range req.RequiredClaims {
		// For required claims, check if user has it on any registered contract or via default claims
		hasClaimOnAnyContract := false
		for _, access := range perms.ContractAccess {
			if containsClaim(access.Claims, claim) {
				hasClaimOnAnyContract = true
				break
			}
		}
		if !hasClaimOnAnyContract && !containsClaim(perms.DefaultClaims, claim) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("missing required claim: %s", claim),
			}, nil
		}
	}

	// Collect all claims the user has (from all contracts + defaults)
	allClaims := collectAllClaims(perms)

	return &AccessCheckResult{
		Allowed:        true,
		RateLimitRPS:   perms.RateLimitRPS,
		RateLimitDaily: perms.RateLimitDaily,
		Claims:         allClaims,
	}, nil
}

// collectAllClaims returns the union of all claims from all contracts and default claims.
func collectAllClaims(perms *EffectivePermissions) []Claim {
	claimSet := make(map[Claim]bool)

	// Add default claims
	for _, c := range perms.DefaultClaims {
		claimSet[c] = true
	}

	// Add claims from all contracts
	for _, access := range perms.ContractAccess {
		for _, c := range access.Claims {
			claimSet[c] = true
		}
	}

	result := make([]Claim, 0, len(claimSet))
	for c := range claimSet {
		result = append(result, c)
	}
	return result
}

// WriteOpsMap contains write operations that require 'write' claim.
// Note: eth_sendRawTransaction is globally blocked (cannot validate without RLP decoding).
var WriteOpsMap = map[string]bool{
	"eth_sendTransaction": true,
}

// ReadOpsMap contains read operations that require 'read' claim.
var ReadOpsMap = map[string]bool{
	"eth_call":                true,
	"eth_estimateGas":         true,
	"eth_getCode":             true,
	"eth_getBalance":          true,
	"eth_getStorageAt":        true,
	"eth_getTransactionCount": true,
	"eth_getLogs":             true,
}

// ClassifyOperation determines the required claim for a JSON-RPC method.
// Returns the claim needed to execute this operation.
// For eth_sendTransaction and eth_estimateGas, checks params to distinguish
// deployment vs regular transaction/call.
func ClassifyOperation(method string, params []any) Claim {
	// Check for contract deployment FIRST (before general write/read check)
	// This includes both eth_sendTransaction deployments AND eth_estimateGas
	// for deployment gas estimation - both require deploy claim
	if IsContractDeployment(method, params) {
		return ClaimDeploy
	}

	// Write operations require 'write' claim
	if WriteOpsMap[method] {
		return ClaimWrite
	}

	// Read operations require 'read' claim
	if ReadOpsMap[method] {
		return ClaimRead
	}

	// Other methods don't require contract-level claims
	// (e.g., eth_blockNumber, eth_chainId - these are not contract-specific)
	return ""
}

// IsContractDeployment checks if the method+params represent a contract deployment.
// Contract deployments are eth_sendTransaction calls with no 'to' address.
// Also detects eth_estimateGas for deployment (estimating gas for contract creation).
// NOTE: eth_sendRawTransaction is globally blocked because it cannot be validated
// without RLP decoding, which would bypass all RBAC security controls.
func IsContractDeployment(method string, params []any) bool {
	// Only eth_sendTransaction and eth_estimateGas can be validated for deployment
	if method != "eth_sendTransaction" && method != "eth_estimateGas" {
		return false
	}

	if len(params) == 0 {
		// No params means we can't determine if it's a deployment.
		// Return false and let the method-level permissions handle access.
		// The caller can still require specific claims via required_claims.
		return false
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		// Malformed params, treat as deployment to be safe
		return true
	}

	// Check if 'to' field exists and is non-empty
	to, exists := txObj["to"]
	if !exists {
		// No 'to' field = contract deployment
		return true
	}

	// Handle various forms of empty 'to':
	// - nil/null
	// - empty string ""
	// - "0x" (some clients send this for deployment)
	if to == nil {
		return true
	}

	toStr, ok := to.(string)
	if !ok {
		// 'to' is not a string (e.g., number or object), treat as deployment to be safe
		return true
	}

	// Empty string or just "0x" means deployment
	if toStr == "" || toStr == "0x" {
		return true
	}

	// Has a valid 'to' address, not a deployment
	return false
}

// extractDeploymentBytecode extracts the bytecode from contract deployment params.
// For eth_sendTransaction and eth_estimateGas, the bytecode is in the "data" or "input" field.
// Returns empty string if bytecode cannot be extracted.
func extractDeploymentBytecode(method string, params []any) string {
	if method != "eth_sendTransaction" && method != "eth_estimateGas" {
		return ""
	}

	if len(params) == 0 {
		return ""
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return ""
	}

	// Try "data" field first (standard), then "input" field (some clients use this)
	if data, ok := txObj["data"].(string); ok && data != "" && data != "0x" {
		return data
	}
	if input, ok := txObj["input"].(string); ok && input != "" && input != "0x" {
		return input
	}

	return ""
}

// extractCalldata extracts the calldata from transaction params as raw bytes.
// For eth_sendTransaction, the calldata is in the "data" or "input" field.
// Returns nil if calldata cannot be extracted or is empty.
func extractCalldata(method string, params []any) []byte {
	if method != "eth_sendTransaction" {
		return nil
	}

	if len(params) == 0 {
		return nil
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return nil
	}

	// Try "data" field first (standard), then "input" field (some clients use this)
	var hexData string
	if data, ok := txObj["data"].(string); ok && data != "" && data != "0x" {
		hexData = data
	} else if input, ok := txObj["input"].(string); ok && input != "" && input != "0x" {
		hexData = input
	}

	if hexData == "" {
		return nil
	}

	// Remove 0x prefix if present
	hexData = strings.TrimPrefix(hexData, "0x")

	// Decode hex to bytes
	calldata, err := hex.DecodeString(hexData)
	if err != nil {
		return nil
	}

	return calldata
}

// containsClaim checks if a claim is in a slice.
func containsClaim(claims []Claim, claim Claim) bool {
	for _, c := range claims {
		if c == claim {
			return true
		}
	}
	return false
}

// GetTargetAddress extracts the target address from JSON-RPC params.
func GetTargetAddress(method string, params []any) string {
	if len(params) == 0 {
		return ""
	}

	switch method {
	case "eth_call", "eth_estimateGas":
		if callObj, ok := params[0].(map[string]any); ok {
			if to, ok := callObj["to"].(string); ok {
				return strings.ToLower(to)
			}
		}
	case "eth_sendTransaction":
		if txObj, ok := params[0].(map[string]any); ok {
			if to, ok := txObj["to"].(string); ok {
				return strings.ToLower(to)
			}
		}
	case "eth_getCode", "eth_getBalance", "eth_getStorageAt", "eth_getTransactionCount":
		if addr, ok := params[0].(string); ok {
			return strings.ToLower(addr)
		}
	}

	return ""
}

// extractBlockParam extracts the block parameter from JSON-RPC params.
// For eth_call: params are [txObject, blockParam] - block is 2nd param
// For eth_getStorageAt: params are [address, slot, blockParam] - block is 3rd param
// Returns the block parameter as string, or "latest" if not specified.
func extractBlockParam(method string, params []any) string {
	if len(params) == 0 {
		return "latest"
	}

	var blockParamIndex int
	switch method {
	case "eth_call":
		blockParamIndex = 1
	case "eth_getStorageAt":
		blockParamIndex = 2
	default:
		return "latest"
	}

	if len(params) <= blockParamIndex {
		return "latest"
	}

	blockParam := params[blockParamIndex]
	if blockParam == nil {
		return "latest"
	}

	blockStr, ok := blockParam.(string)
	if !ok {
		// Non-string block param (e.g., number or block object) - treat as historical for safety
		return "historical"
	}

	if blockStr == "" {
		return "latest"
	}

	return blockStr
}

// isHistoricalBlock checks if a block parameter represents a historical state query.
// Returns true for block numbers (hex like "0x1234") and block hashes.
// Returns false for "latest", "pending", "safe", "finalized", "earliest", or empty string.
func isHistoricalBlock(blockParam string) bool {
	// Empty defaults to "latest" (not historical)
	if blockParam == "" {
		return false
	}

	// Named block tags are NOT historical
	switch strings.ToLower(blockParam) {
	case "latest", "pending", "safe", "finalized", "earliest":
		return false
	}

	// Anything else is considered historical:
	// - Hex block numbers like "0x1234"
	// - Block hashes (66 character hex strings)
	// - Block objects (if someone passes one)
	return true
}

// IsHistoricalStateQuery checks if a request is attempting to query historical blockchain state.
// Returns (isHistorical, reason) where reason explains why it was flagged as historical.
// This is a privacy protection measure to prevent queries at specific past blocks.
func IsHistoricalStateQuery(method string, params []any) (bool, string) {
	// Only check methods that accept block parameters for state queries
	if method != "eth_call" && method != "eth_getStorageAt" {
		return false, ""
	}

	blockParam := extractBlockParam(method, params)
	if isHistoricalBlock(blockParam) {
		return true, "historical state queries not permitted"
	}

	return false, ""
}

// GetFunctionSelector extracts the function selector (first 4 bytes) from calldata.
// Returns empty string if no valid selector found.
// Expects selector format "0xXXXXXXXX" (10 characters including 0x prefix).
func GetFunctionSelector(method string, params []any) string {
	if len(params) == 0 {
		return ""
	}

	// Only extract selectors for contract call methods
	switch method {
	case "eth_call", "eth_estimateGas":
		if callObj, ok := params[0].(map[string]any); ok {
			if data, ok := callObj["data"].(string); ok && len(data) >= 10 {
				// Return first 4 bytes (10 chars including 0x prefix)
				return strings.ToLower(data[:10])
			}
		}
	case "eth_sendTransaction":
		if txObj, ok := params[0].(map[string]any); ok {
			if data, ok := txObj["data"].(string); ok && len(data) >= 10 {
				return strings.ToLower(data[:10])
			}
		}
	}

	return ""
}

// ValidateGetLogsAccess validates eth_getLogs access based on address filter.
// SECURITY: This function enforces that:
// 1. eth_getLogs MUST have an address filter (prevent broad queries)
// 2. User must have 'read' claim on ALL addresses in the filter
// This prevents users from querying logs from contracts they shouldn't see,
// enforcing cross-org isolation.
func ValidateGetLogsAccess(perms *EffectivePermissions, params []any) error {
	if len(params) == 0 {
		return fmt.Errorf("eth_getLogs: missing filter parameter")
	}

	filterObj, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("eth_getLogs: invalid filter parameter type")
	}

	// Extract addresses from filter
	addresses := extractGetLogsAddresses(filterObj)

	// SECURITY: Require address filter to prevent broad queries
	// Without this check, users could query ALL logs on the chain
	if len(addresses) == 0 {
		return fmt.Errorf("eth_getLogs: address filter required for security")
	}

	// Check each address against RBAC permissions
	for _, addr := range addresses {
		access := perms.GetContractAccess(addr)
		if access == nil {
			return fmt.Errorf("eth_getLogs: no access to contract %s", addr)
		}
		if !containsClaim(access.Claims, ClaimRead) {
			return fmt.Errorf("eth_getLogs: missing read claim on contract %s", addr)
		}
	}

	return nil
}

// extractGetLogsAddresses extracts contract addresses from eth_getLogs filter.
// The address field can be:
// - A single address string: "0x..."
// - An array of address strings: ["0x...", "0x..."]
// - null/missing (returns empty slice)
func extractGetLogsAddresses(filter map[string]any) []string {
	var addresses []string

	addrField := filter["address"]
	if addrField == nil {
		return nil
	}

	// Can be a single address string
	if addr, ok := addrField.(string); ok {
		if addr != "" {
			addresses = append(addresses, strings.ToLower(addr))
		}
		return addresses
	}

	// Or an array of addresses
	if addrArray, ok := addrField.([]any); ok {
		for _, a := range addrArray {
			if addr, ok := a.(string); ok && addr != "" {
				addresses = append(addresses, strings.ToLower(addr))
			}
		}
	}

	return addresses
}

// GetGetLogsAddresses is an exported version for use by external callers.
// Returns the list of addresses from eth_getLogs filter params.
func GetGetLogsAddresses(params []any) []string {
	if len(params) == 0 {
		return nil
	}

	filterObj, ok := params[0].(map[string]any)
	if !ok {
		return nil
	}

	return extractGetLogsAddresses(filterObj)
}

// validateGetLogsAccessWithCrossOrgCheck validates eth_getLogs access with cross-org isolation.
// This extends ValidateGetLogsAccess to also check that contracts accessed via default_claims
// are not registered to other organizations (P0 security fix).
func (c *AccessController) validateGetLogsAccessWithCrossOrgCheck(ctx context.Context, perms *EffectivePermissions, params []any) error {
	if len(params) == 0 {
		return fmt.Errorf("eth_getLogs: missing filter parameter")
	}

	filterObj, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("eth_getLogs: invalid filter parameter type")
	}

	// Extract addresses from filter
	addresses := extractGetLogsAddresses(filterObj)

	// SECURITY: Require address filter to prevent broad queries
	// Without this check, users could query ALL logs on the chain
	if len(addresses) == 0 {
		return fmt.Errorf("eth_getLogs: address filter required for security")
	}

	// Check each address against RBAC permissions with cross-org isolation
	for _, addr := range addresses {
		// Check if user has EXPLICIT access to this contract
		hasExplicitAccess := perms.IsContractRegistered(addr)

		access := perms.GetContractAccess(addr)
		if access == nil {
			return fmt.Errorf("eth_getLogs: no access to contract %s", addr)
		}
		if !containsClaim(access.Claims, ClaimRead) {
			return fmt.Errorf("eth_getLogs: missing read claim on contract %s", addr)
		}

		// CROSS-ORG ISOLATION CHECK (P0 Security Fix)
		// If user doesn't have explicit access but got access via default_claims,
		// verify the contract isn't registered to any other organization.
		if !hasExplicitAccess {
			isRegisteredToAnyOrg, err := c.store.IsContractRegisteredToAnyOrg(ctx, addr)
			if err != nil {
				return fmt.Errorf("eth_getLogs: failed to check contract registration: %w", err)
			}
			if isRegisteredToAnyOrg {
				return fmt.Errorf("eth_getLogs: contract %s is registered to another organization", addr)
			}
		}
	}

	return nil
}

// EnsureUserExists creates a user if they don't exist, or returns the existing user.
// This is used during authentication to ensure users are in the RBAC system.
// The kyc parameter is only used for NEW users; existing users retain their KYC status
// (KYC status should be managed via admin API, not overwritten during auth).
func (c *AccessController) EnsureUserExists(ctx context.Context, externalID string, kyc bool) (*User, error) {
	user, err := c.store.GetUserByExternalID(ctx, externalID)
	if err != nil {
		return nil, err
	}

	if user != nil {
		// Return existing user without modifying their KYC status
		// KYC is admin-managed and should not be changed during authentication
		return user, nil
	}

	// Create new user
	user = &User{
		ID:         uuid.New().String(),
		ExternalID: externalID,
		KYC:        kyc,
		Banned:     false,
		Metadata:   make(map[string]any),
	}

	if err := c.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Add user to default group
	membership := &UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: DefaultGroupID,
		Source:  MembershipSourceAdmin,
	}

	if err := c.store.CreateMembership(ctx, membership); err != nil {
		// Log but don't fail - user is created
		log.Printf("Warning: failed to add user %s to default group: %v", user.ID, err)
	}

	// Audit log
	c.store.CreateAuditLog(ctx, &AuditLogEntry{
		Action:       AuditActionCreate,
		ResourceType: ResourceTypeUser,
		ResourceID:   &user.ID,
		ResourceName: externalID,
		NewValue: map[string]any{
			"external_id": externalID,
			"kyc":         kyc,
		},
	})

	return user, nil
}

// InvalidateUser invalidates cached permissions for a user.
func (c *AccessController) InvalidateUser(ctx context.Context, userID string) error {
	c.cache.InvalidateUser(userID)
	return c.resolver.InvalidateUserPermissions(ctx, userID)
}

// InvalidateOrg invalidates cached permissions for all users in an organization.
func (c *AccessController) InvalidateOrg(ctx context.Context, orgID string) error {
	c.cache.InvalidateOrg(orgID)
	return c.resolver.InvalidateOrgPermissions(ctx, orgID)
}

// InvalidateGroup invalidates cached permissions for all users in a group.
func (c *AccessController) InvalidateGroup(ctx context.Context, groupID string) error {
	// Get the group to find its org_id for cache invalidation
	group, err := c.store.GetGroup(ctx, groupID)
	if err == nil && group != nil {
		// Invalidate the in-memory cache for the entire org (safest approach)
		c.cache.InvalidateOrg(group.OrgID)
	}
	return c.resolver.InvalidateGroupPermissions(ctx, groupID)
}

// GetEffectivePermissions returns the effective permissions for a user in an organization.
func (c *AccessController) GetEffectivePermissions(ctx context.Context, userExternalID, orgSlug string) (*EffectivePermissions, error) {
	user, err := c.store.GetUserByExternalID(ctx, userExternalID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found: %s", userExternalID)
	}

	if orgSlug == "" {
		orgSlug = "default"
	}

	org, err := c.store.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, fmt.Errorf("organization not found: %s", orgSlug)
	}

	return c.resolver.ResolvePermissions(ctx, user.ID, org.ID)
}

// CacheStats returns statistics about the in-memory cache.
func (c *AccessController) CacheStats() CacheStats {
	return c.cache.Stats()
}

// Stop stops the access controller's background goroutines.
func (c *AccessController) Stop() {
	c.cache.Stop()
}

// TrackPendingDeployment tracks a pending proxy deployment for later registration.
// This should be called by the RPC layer after successfully forwarding a deployment
// transaction that was validated as a proxy.
//
// Parameters:
//   - txHash: The transaction hash returned by eth_sendTransaction
//   - orgID: The organization ID that owns the deployment
//   - proxyType: The detected proxy type (e.g., "ERC1967", "Transparent", "UUPS")
//   - proxyInfo: The full proxy detection info from validation
func (c *AccessController) TrackPendingDeployment(
	txHash string,
	orgID string,
	proxyType string,
	proxyInfo *bytecode.ProxyInfo,
) {
	if txHash == "" || orgID == "" {
		return
	}

	deployment := &PendingDeployment{
		TxHash:      txHash,
		OrgID:       orgID,
		IsProxy:     proxyInfo != nil && proxyInfo.IsProxy,
		ProxyType:   proxyType,
		ProxyInfo:   proxyInfo,
		SubmittedAt: time.Now(),
	}

	c.pendingTracker.Track(txHash, deployment)
}

// NotifyDeploymentMined processes a mined deployment transaction.
// This should be called by the RPC layer after receiving the transaction receipt.
//
// Parameters:
//   - ctx: Context for database operations
//   - txHash: The transaction hash of the mined deployment
//   - contractAddress: The address of the deployed contract from the receipt
//
// Returns nil if the deployment was not tracked (not a proxy) or was successfully registered.
// Returns an error if proxy registration fails.
func (c *AccessController) NotifyDeploymentMined(
	ctx context.Context,
	txHash string,
	contractAddress string,
) error {
	// Get the pending deployment (removes it from tracker)
	deployment := c.pendingTracker.Get(txHash)
	if deployment == nil {
		// Not a tracked deployment - this is fine
		return nil
	}

	// Only register if it's a proxy
	if !deployment.IsProxy || deployment.ProxyInfo == nil {
		return nil
	}

	// Register the deployed proxy
	return c.deployValidator.RegisterDeployedProxy(
		ctx,
		deployment.OrgID,
		contractAddress,
		deployment.ProxyInfo,
		"", // Initial implementation not known from deployment bytecode
	)
}

// GetPendingDeployment retrieves a pending deployment without removing it.
// This is useful for checking if a transaction is being tracked.
func (c *AccessController) GetPendingDeployment(txHash string) *PendingDeployment {
	return c.pendingTracker.Peek(txHash)
}

// PendingDeploymentCount returns the number of pending deployments being tracked.
func (c *AccessController) PendingDeploymentCount() int {
	return c.pendingTracker.Size()
}

// CleanupPendingDeployments removes expired pending deployments.
// Returns the number of entries removed.
func (c *AccessController) CleanupPendingDeployments() int {
	return c.pendingTracker.Cleanup()
}

// DeploymentValidator returns the deployment validator for direct use.
// This is useful when the caller needs to access validation results for proxy tracking.
func (c *AccessController) DeploymentValidator() *DeploymentValidator {
	return c.deployValidator
}
