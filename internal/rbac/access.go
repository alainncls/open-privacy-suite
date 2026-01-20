package rbac

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GlobalBlockedMethods contains methods that are NEVER allowed regardless of RBAC permissions.
// These methods pose security risks and should never be exposed through the proxy.
var GlobalBlockedMethods = []string{
	// Debug namespace - information disclosure, DoS risk
	"debug_accountRange",
	"debug_backtraceAt",
	"debug_blockProfile",
	"debug_chaindbCompact",
	"debug_chaindbProperty",
	"debug_cpuProfile",
	"debug_dbAncient",
	"debug_dbAncients",
	"debug_dbGet",
	"debug_dumpBlock",
	"debug_freeOSMemory",
	"debug_freezeClient",
	"debug_gcStats",
	"debug_getBadBlocks",
	"debug_getHeaderRlp",
	"debug_getModifiedAccountsByHash",
	"debug_getModifiedAccountsByNumber",
	"debug_goTrace",
	"debug_intermediateRoots",
	"debug_memStats",
	"debug_mutexProfile",
	"debug_preimage",
	"debug_printBlock",
	"debug_seedHash",
	"debug_setBlockProfileRate",
	"debug_setGCPercent",
	"debug_setHead",
	"debug_setMutexProfileFraction",
	"debug_stacks",
	"debug_standardTraceBadBlockToFile",
	"debug_standardTraceBlockToFile",
	"debug_startCPUProfile",
	"debug_startGoTrace",
	"debug_stopCPUProfile",
	"debug_stopGoTrace",
	"debug_storageRangeAt",
	"debug_subscribe",
	"debug_traceBadBlock",
	"debug_traceBlock",
	"debug_traceBlockByHash",
	"debug_traceBlockByNumber",
	"debug_traceBlockFromFile",
	"debug_traceCall",
	"debug_traceChain",
	"debug_traceTransaction",
	"debug_unsubscribe",
	"debug_verbosity",
	"debug_vmodule",
	"debug_writeBlockProfile",
	"debug_writeMemProfile",
	"debug_writeMutexProfile",

	// Admin namespace - node administration
	"admin_addPeer",
	"admin_addTrustedPeer",
	"admin_clearHistory",
	"admin_datadir",
	"admin_exportChain",
	"admin_importChain",
	"admin_nodeInfo",
	"admin_peers",
	"admin_removePeer",
	"admin_removeTrustedPeer",
	"admin_sleep",
	"admin_sleepBlocks",
	"admin_startHTTP",
	"admin_startRPC",
	"admin_startWS",
	"admin_stopHTTP",
	"admin_stopRPC",
	"admin_stopWS",

	// Personal namespace - key exposure risk
	"personal_deriveAccount",
	"personal_ecRecover",
	"personal_importRawKey",
	"personal_initializeWallet",
	"personal_listAccounts",
	"personal_listWallets",
	"personal_lockAccount",
	"personal_newAccount",
	"personal_openWallet",
	"personal_sendTransaction",
	"personal_sign",
	"personal_signTransaction",
	"personal_unlockAccount",
	"personal_unpair",

	// Miner namespace - MEV risk, node control
	"miner_getHashrate",
	"miner_setEtherbase",
	"miner_setExtra",
	"miner_setGasLimit",
	"miner_setGasPrice",
	"miner_setRecommitInterval",
	"miner_start",
	"miner_stop",

	// Txpool namespace - MEV risk, information disclosure
	"txpool_content",
	"txpool_contentFrom",
	"txpool_inspect",
	"txpool_status",

	// Signing methods - key exposure risk
	"eth_sign",
	"eth_signTransaction",

	// Clique namespace - consensus manipulation
	"clique_discard",
	"clique_getSigners",
	"clique_getSignersAtHash",
	"clique_getSnapshot",
	"clique_getSnapshotAtHash",
	"clique_proposals",
	"clique_propose",
	"clique_status",

	// Les namespace - light client control
	"les_addBalance",
	"les_clientInfo",
	"les_latestCheckpoint",
	"les_priorityClientInfo",
	"les_serverInfo",
	"les_setClientParams",
	"les_setDefaultParams",
}

// IsMethodBlocked checks if a method is globally blocked.
func IsMethodBlocked(method string) bool {
	// Check exact match
	if slices.Contains(GlobalBlockedMethods, method) {
		return true
	}

	// Also block any method starting with blocked prefixes (for future-proofing)
	blockedPrefixes := []string{
		"debug_",
		"admin_",
		"personal_",
		"miner_",
		"txpool_",
		"clique_",
		"les_",
	}
	for _, prefix := range blockedPrefixes {
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
	"0x252dba42": "aggregate",        // aggregate((address,bytes)[])
	"0x82ad56cb": "aggregate3",       // aggregate3((address,bool,bytes)[])
	"0x174dea71": "aggregate3Value",  // aggregate3Value((address,bool,uint256,bytes)[])
	"0xc3077fa9": "blockAndAggregate", // blockAndAggregate((address,bytes)[])
	"0xbce38bd7": "tryAggregate",     // tryAggregate(bool,(address,bytes)[])
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
	cacheKey := user.ID + ":" + org.ID
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

	// Check contract access if specified
	if req.ContractAddress != "" {
		addr := strings.ToLower(req.ContractAddress)
		if !perms.HasContract(addr) && !perms.OwnsContract(addr) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("contract %s not allowed", req.ContractAddress),
			}, nil
		}

		// Check function selector if specified and contract has function restrictions
		if req.FunctionSelector != "" {
			selector := strings.ToLower(req.FunctionSelector)
			if !perms.HasFunctionSelector(addr, selector) {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  fmt.Sprintf("function %s not allowed on contract %s", req.FunctionSelector, req.ContractAddress),
				}, nil
			}
		}
	}

	// Check required claims
	for _, claim := range req.RequiredClaims {
		if !perms.HasClaim(claim) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("missing required claim: %s", claim),
			}, nil
		}
	}

	// Use _ to prevent unused variable warning
	_ = cacheKey

	return &AccessCheckResult{
		Allowed:        true,
		RateLimitRPS:   perms.RateLimitRPS,
		RateLimitDaily: perms.RateLimitDaily,
		Claims:         perms.Claims,
	}, nil
}

// ClassifyOperation determines the required claims for a JSON-RPC method.
func ClassifyOperation(method string, params []any) []Claim {
	// Deploy operation: eth_sendTransaction with empty "to" field
	if method == "eth_sendTransaction" && len(params) > 0 {
		if txObj, ok := params[0].(map[string]any); ok {
			to, hasTo := txObj["to"]
			if !hasTo || to == nil || to == "" {
				return []Claim{ClaimDeployer}
			}
		}
	}

	// Write operations
	writeOps := []string{
		"eth_sendTransaction",
		"eth_sendRawTransaction",
	}
	if slices.Contains(writeOps, method) {
		return []Claim{ClaimWriter}
	}

	// Read operations (everything else)
	return []Claim{ClaimReader}
}

// GetContractAddress extracts the contract address from JSON-RPC params.
func GetContractAddress(method string, params []any) string {
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

	// Add user to default group with default role
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	defaultGroupID := "00000000-0000-0000-0000-000000000001"
	defaultRoleID := "00000000-0000-0000-0000-000000000003" // user role

	membership := &UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: defaultGroupID,
		RoleID:  &defaultRoleID,
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
			"org_id":      defaultOrgID,
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
