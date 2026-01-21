package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

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
func DetectMulticall(method string, params []any) (bool, string) {
	if method != "eth_call" && method != "eth_estimateGas" {
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
	store    Store
	resolver *Resolver
	cache    *Cache
}

// NewAccessController creates a new access controller.
func NewAccessController(store Store, cacheTTL time.Duration) *AccessController {
	return &AccessController{
		store:    store,
		resolver: NewResolver(store, cacheTTL),
		cache:    NewCache(CacheConfig{TTL: cacheTTL}),
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

	// Determine required claim based on the operation
	requiredClaim := ClassifyOperation(req.Method, req.Params)

	// Check contract access if target address is specified
	if req.TargetAddress != "" {
		addr := strings.ToLower(req.TargetAddress)

		// Get contract access for this address
		access := perms.GetContractAccess(addr)

		// If no access to this contract (not registered and no default claims), deny
		if access == nil {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("no access to contract %s", req.TargetAddress),
			}, nil
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
var WriteOpsMap = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
}

// ReadOpsMap contains read operations that require 'read' claim.
var ReadOpsMap = map[string]bool{
	"eth_call":                true,
	"eth_estimateGas":         true,
	"eth_getCode":             true,
	"eth_getBalance":          true,
	"eth_getStorageAt":        true,
	"eth_getTransactionCount": true,
}

// ClassifyOperation determines the required claim for a JSON-RPC method.
// Returns the claim needed to execute this operation.
func ClassifyOperation(method string, params []any) Claim {
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
	defaultGroupID := "00000000-0000-0000-0000-000000000001"

	membership := &UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: defaultGroupID,
		Source:  MembershipSourceAdmin,
	}

	if err := c.store.CreateMembership(ctx, membership); err != nil {
		// Log but don't fail - user is created
		_ = err
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
