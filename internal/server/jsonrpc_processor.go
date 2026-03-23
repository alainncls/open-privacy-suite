package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

// JSONRPCProcessor handles the business logic for JSON-RPC requests.
// It separates concerns from HTTP handling, making the logic testable
// and reusable.
type JSONRPCProcessor struct {
	rbacAccessCtrl    *rbac.AccessController
	rateLimiter       RateLimiterInterface
	proxy             *proxy.Proxy
	accessLogger      AccessLogger
	runtimeTracer     *tracer.RuntimeTracer
	traceValidator    *rbac.TraceValidator
	complianceChecker *compliance.Checker

	// Enhanced audit fields
	enhancedLogger EnhancedAccessLogger
	hashChain      *audit.HashChain
	siemForwarder  *audit.SIEMForwarder
	logParams      bool

	// Prometheus metrics
	metrics *metrics.Metrics
}

// AccessLogger logs access attempts for auditing.
type AccessLogger interface {
	LogAccess(ctx context.Context, userID, method string, statusCode int, clientIP string) error
}

// EnhancedAccessLogger logs access with correlation ID, params, and returns the entry ID for hash chain.
type EnhancedAccessLogger interface {
	LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte) (int64, time.Time, error)
	UpdateAccessLogHash(ctx context.Context, id int64, hash string) error
}

// ProcessRequest represents a validated JSON-RPC request ready for processing.
type ProcessRequest struct {
	UserID        string
	OrgID         string // Optional: specify which org to use (for users with multiple memberships)
	Method        string
	Params        []any
	Body          []byte
	ClientIP      string
	CorrelationID string // Request correlation ID for audit trail
}

// ProcessResult represents the result of processing a JSON-RPC request.
type ProcessResult struct {
	StatusCode   int
	ResponseBody []byte
	Error        *ProcessError
}

// ProcessError represents an error during request processing.
type ProcessError struct {
	StatusCode int
	Message    string
}

func (e *ProcessError) Error() string {
	return e.Message
}

// NewJSONRPCProcessor creates a new processor with the given dependencies.
func NewJSONRPCProcessor(
	rbacCtrl *rbac.AccessController,
	rateLimiter RateLimiterInterface,
	proxyClient *proxy.Proxy,
	logger AccessLogger,
) *JSONRPCProcessor {
	return &JSONRPCProcessor{
		rbacAccessCtrl: rbacCtrl,
		rateLimiter:    rateLimiter,
		proxy:          proxyClient,
		accessLogger:   logger,
	}
}

// SetComplianceChecker sets the compliance checker for travel rule enforcement.
func (p *JSONRPCProcessor) SetComplianceChecker(checker *compliance.Checker) {
	p.complianceChecker = checker
}

// SetEnhancedAudit configures enhanced audit logging with hash chain and optional SIEM.
func (p *JSONRPCProcessor) SetEnhancedAudit(logger EnhancedAccessLogger, hashChain *audit.HashChain, siemForwarder *audit.SIEMForwarder, logParams bool) {
	p.enhancedLogger = logger
	p.hashChain = hashChain
	p.siemForwarder = siemForwarder
	p.logParams = logParams
}

// SetMetrics configures Prometheus metrics for the processor.
func (p *JSONRPCProcessor) SetMetrics(m *metrics.Metrics) {
	p.metrics = m
}

// logAccess logs an access entry using enhanced logging (with hash chain + SIEM) if available,
// falling back to the basic logger.
func (p *JSONRPCProcessor) logAccess(ctx context.Context, req *ProcessRequest, statusCode int, responseStatus ...int) {
	respStatus := statusCode
	if len(responseStatus) > 0 {
		respStatus = responseStatus[0]
	}

	if p.enhancedLogger != nil && p.hashChain != nil {
		var params []byte
		if p.logParams && req.Params != nil {
			params = audit.RedactParams(req.Method, req.Params)
		}

		id, createdAt, err := p.enhancedLogger.LogAccessEnhanced(ctx, req.UserID, req.Method, statusCode, req.ClientIP, req.CorrelationID, params)
		if err != nil {
			// Fallback to basic logging
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
			return
		}

		// Compute and store hash chain entry
		// Both decision status and response status are committed to the chain
		paramsDigest := ""
		if len(params) > 0 {
			paramsDigest = string(params)
		}
		entryContent := fmt.Sprintf("%d|%s|%s|%s|%d|%d|%s|%s|%s",
			id, req.UserID, req.Method, req.ClientIP, statusCode, respStatus,
			createdAt.Format(time.RFC3339Nano),
			req.CorrelationID,
			paramsDigest,
		)
		hash := p.hashChain.ComputeNext(entryContent)
		if err := p.enhancedLogger.UpdateAccessLogHash(ctx, id, hash); err != nil {
			slog.Warn("failed to update access log hash", "id", id, "error", err)
		}

		// Forward to SIEM if configured
		if p.siemForwarder != nil {
			outcome := "success"
			if statusCode >= 400 {
				outcome = "denied"
			}
			if statusCode >= 500 {
				outcome = "error"
			}
			p.siemForwarder.Send(audit.SIEMEvent{
				Timestamp:     createdAt,
				EventType:     "access",
				CorrelationID: req.CorrelationID,
				ActorID:       req.UserID,
				Action:        req.Method,
				Outcome:       outcome,
				Details:       fmt.Sprintf("decision=%d response=%d", statusCode, respStatus),
				SourceIP:      req.ClientIP,
				EntryHash:     hash,
			})
		}
		return
	}

	// Fallback to basic logging
	p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
}

// NewJSONRPCProcessorWithTracing creates a new processor with runtime tracing support.
func NewJSONRPCProcessorWithTracing(
	rbacCtrl *rbac.AccessController,
	rateLimiter RateLimiterInterface,
	proxyClient *proxy.Proxy,
	logger AccessLogger,
	runtimeTracer *tracer.RuntimeTracer,
	traceValidator *rbac.TraceValidator,
) *JSONRPCProcessor {
	return &JSONRPCProcessor{
		rbacAccessCtrl: rbacCtrl,
		rateLimiter:    rateLimiter,
		proxy:          proxyClient,
		accessLogger:   logger,
		runtimeTracer:  runtimeTracer,
		traceValidator: traceValidator,
	}
}

// ParseAndValidateBody parses and validates the JSON-RPC request body.
// Returns the method, params, and any validation error.
func ParseAndValidateBody(body []byte) (string, []any, *ProcessError) {
	if len(body) > MaxRequestBodySize {
		return "", nil, &ProcessError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Message:    "request body too large",
		}
	}

	method, params, err := proxy.ParseRequest(body)
	if err != nil {
		if err == proxy.ErrBatchRequest {
			return "", nil, &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "batch JSON-RPC requests are not supported for security reasons",
			}
		}
		return "", nil, &ProcessError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid JSON-RPC request: " + err.Error(),
		}
	}

	return method, params, nil
}

// Process handles the core business logic for a JSON-RPC request:
// 1. RBAC access check
// 2. Runtime tracing (if enabled, for eth_sendTransaction and eth_sendRawTransaction)
// 3. Rate limiting
// 4. Forwarding to the target node
func (p *JSONRPCProcessor) Process(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	// Handle eth_sendRawTransaction specially - requires runtime tracing
	if req.Method == "eth_sendRawTransaction" {
		return p.processRawTransaction(ctx, req)
	}

	// Handle debug traces specially - requires strict deep tree validation
	if req.Method == "debug_traceTransaction" || req.Method == "debug_traceCall" {
		return p.processDebugTrace(ctx, req)
	}

	// Build RBAC access check request
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(req.Method, req.Params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}

	targetAddr := rbac.GetTargetAddress(req.Method, req.Params)

	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           req.Method,
		Params:           req.Params,
		TargetAddress:    targetAddr,
		FunctionSelector: rbac.GetFunctionSelector(req.Method, req.Params),
		RequiredClaims:   requiredClaims,
	}

	// Check RBAC access
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		slog.Error("RBAC access check failed", "method", req.Method, "error", err)
		p.recordRPCOutcome(req.Method, "error", start)
		p.logAccess(ctx, req, http.StatusInternalServerError, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}

	if !result.Allowed {
		realStatus := http.StatusForbidden
		if result.AuthRequired {
			realStatus = http.StatusUnauthorized
		}
		slog.Info("RBAC access denied", "method", req.Method, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "reason", result.Reason)
		p.recordRPCOutcome(req.Method, "rbac_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, realStatus, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}
	p.recordRBACDecision("allowed")

	// Runtime tracing: validate all call targets for eth_sendTransaction
	runtimeCreateTargets, traceErr := p.validateWithTracing(ctx, req, targetAddr)
	if traceErr != nil {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: traceErr,
		}
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if req.Method == "eth_sendTransaction" {
		from, to, data, value := extractTxParams(req.Params)
		if compErr := p.checkCompliance(ctx, req, result.OrgID, result.UserID, from, to, data, value); compErr != nil {
			return compErr
		}
	}

	// Check rate limits
	allowed, rateLimitReason := p.rateLimiter.CheckAndIncrement(req.UserID, result.RateLimitRPS, result.RateLimitDaily)
	if !allowed {
		p.recordRPCOutcome(req.Method, "rate_limited", start)
		if p.metrics != nil {
			p.metrics.RateLimitHitsTotal.WithLabelValues("rpc").Inc()
		}
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    rateLimitReason,
			},
		}
	}

	// Pre-register plain CREATE deployments to close the cross-org race window.
	// We do this as late as possible (after rate limiting) to avoid orphaned rows.
	var plainCreatePreRegAddr string
	if req.Method == "eth_sendTransaction" {
		from, to, _, _ := extractTxParams(req.Params)
		isPlainCreate := from != "" && (to == "" || to == "0x")
		if isPlainCreate {
			var preErr error
			plainCreatePreRegAddr, preErr = p.preRegisterPlainCreate(ctx, result.OrgID, result.UserID, req.Params)
			if preErr != nil {
				// Non-fatal: log and continue without pre-registration.
				// The cross-org window remains open for this tx, but the tx still proceeds.
				slog.Warn("plain CREATE pre-registration failed", "error", preErr)
				plainCreatePreRegAddr = ""
			}
		}
	}

	// Pre-register runtime CREATE/CREATE2 addresses discovered during trace validation.
	var runtimeCreateAddrs []string
	if len(runtimeCreateTargets) > 0 && req.Method == "eth_sendTransaction" {
		runtimeCreateAddrs = p.preRegisterRuntimeCreates(ctx, result.OrgID, runtimeCreateTargets)
	}

	// Prepare forward body by rewriting certain queries to ensure we get full tx objects
	forwardBody := req.Body
	if req.Method == "eth_getBlockByNumber" || req.Method == "eth_getBlockByHash" {
		isFull := false // JSON-RPC spec defaults missing to false (hashes only)
		if len(req.Params) >= 2 {
			if val, ok := req.Params[1].(bool); ok {
				isFull = val
			}
		}
		if !isFull {
			if rewriten := rewriteToFullTxObjects(req.Body, req.Params); rewriten != nil {
				forwardBody = rewriten
			}
		}
	} else if req.Method == "eth_getBlockTransactionCountByNumber" {
		if rewriten := rewriteToGetBlock(req.Body, "eth_getBlockByNumber", req.Params); rewriten != nil {
			forwardBody = rewriten
		}
	} else if req.Method == "eth_getBlockTransactionCountByHash" {
		if rewriten := rewriteToGetBlock(req.Body, "eth_getBlockByHash", req.Params); rewriten != nil {
			forwardBody = rewriten
		}
	}

	// Forward to node
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.Forward(forwardBody)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}
	if err != nil {
		p.recordRPCOutcome(req.Method, "forward_error", start)
		p.logAccess(ctx, req, http.StatusBadGateway)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadGateway,
				Message:    fmt.Sprintf("failed to forward request: %v", err),
			},
		}
	}

	// Auto-register contract if this was a successful factory deploy
	if result.FactoryDeployInfo != nil && statusCode == http.StatusOK {
		p.autoRegisterFactoryDeploy(ctx, result.FactoryDeployInfo, responseBody)
	}

	// Handle plain CREATE pre-registration tracking/cleanup.
	if plainCreatePreRegAddr != "" {
		var rpcResp struct {
			Result string `json:"result"`
			Error  *struct{ Message string `json:"message"` } `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp) == nil &&
			rpcResp.Error == nil &&
			rpcResp.Result != ""

		if nodeAccepted {
			// Track and start background receipt polling.
			p.rbacAccessCtrl.TrackPlainCreateDeployment(rpcResp.Result, result.OrgID, result.UserID, plainCreatePreRegAddr)
			p.pollAndFinalizePlainCreate(rpcResp.Result, plainCreatePreRegAddr, result.OrgID, result.UserID)
		} else {
			// Node rejected the tx — delete the pre-registration immediately.
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), plainCreatePreRegAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", plainCreatePreRegAddr, "error", delErr)
			}
		}
	}

	// Handle runtime CREATE/CREATE2 tracking/cleanup.
	if len(runtimeCreateAddrs) > 0 {
		var rpcResp2 struct {
			Result string                         `json:"result"`
			Error  *struct{ Message string `json:"message"` } `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp2) == nil &&
			rpcResp2.Error == nil &&
			rpcResp2.Result != ""

		if nodeAccepted {
			go p.pollAndFinalizeRuntimeCreates(rpcResp2.Result, runtimeCreateAddrs, result.OrgID, result.UserID)
		} else {
			// Node rejected — clean up pre-registrations
			for _, addr := range runtimeCreateAddrs {
				if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
					context.Background(), addr); delErr != nil {
					slog.Warn("failed to clean up runtime create pre-registration", "address", addr, "error", delErr)
				}
			}
		}
	}

	// NOTE: eth_sendTransaction is NOT system-linked here. Unlike eth_sendRawTransaction,
	// the `from` field comes from user-supplied params and is not cryptographically verified
	// by the proxy — only the Ethereum node verifies that the account is unlocked.
	// In a shared-node environment (e.g., Anvil with multiple unlocked accounts), a user
	// could forge any unlocked address as `from`. System-linking is only safe for
	// eth_sendRawTransaction where the sender is recovered from the signature.

	// Apply response-level privacy filtering based on method.
	// This filters responses to prevent cross-participant data leakage
	// within the same organization.
	responseBody = p.applyResponseFilter(ctx, req, result, responseBody)

	// Log successful access
	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

// applyResponseFilter applies response-level privacy filters based on the JSON-RPC method.
// This prevents co-participants of the same contract from seeing each other's
// transaction data, event logs, and receipts.
//
// Filters applied:
//   - eth_getTransactionByHash: null for non-participants
//   - eth_getTransactionReceipt: null for non-participants
//   - eth_getLogs: remove log entries where user's address is not in indexed topics
//   - eth_getTransactionByBlockHashAndIndex / eth_getTransactionByBlockNumberAndIndex: null for non-participants
//   - eth_getBlockByHash / eth_getBlockByNumber: remove non-participant txs from block
//   - eth_getBlockReceipts: remove non-participant receipts from array
func (p *JSONRPCProcessor) applyResponseFilter(ctx context.Context, req *ProcessRequest, result *rbac.AccessCheckResult, responseBody []byte) []byte {
	m := req.Method
	switch {
	case strings.EqualFold(m, rbac.MethodGetTransactionByHash):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil || len(addrs) == 0 {
			// No linked addresses -- return null (cannot verify participation)
			id := rpcResponseID(responseBody)
			return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
		}
		return FilterTransactionByHash(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodGetTransactionReceipt):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil || len(addrs) == 0 {
			// No linked addresses -- return null (cannot verify participation)
			return FilterTransactionReceipt(responseBody, nil)
		}
		return FilterTransactionReceipt(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodGetLogs):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil || len(addrs) == 0 {
			// No linked addresses -- return empty logs
			id := rpcResponseID(responseBody)
			return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":[]}`)
		}
		return FilterLogs(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodGetTransactionByBlockHashAndIndex),
		strings.EqualFold(m, rbac.MethodGetTransactionByBlockNumberAndIndex):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil || len(addrs) == 0 {
			id := rpcResponseID(responseBody)
			return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
		}
		return FilterTransactionByHash(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodGetBlockByHash),
		strings.EqualFold(m, rbac.MethodGetBlockByNumber):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			return responseBody // pass through on error
		}
		
		originalFull := false // JSON-RPC defaults false
		if len(req.Params) >= 2 {
			if isFull, ok := req.Params[1].(bool); ok {
				originalFull = isFull
			}
		}
		return FilterBlockTransactions(responseBody, addrs, originalFull)
		
	case strings.EqualFold(m, "eth_getBlockTransactionCountByHash"),
		strings.EqualFold(m, "eth_getBlockTransactionCountByNumber"):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			return FilterBlockTransactionCount(responseBody, nil)
		}
		return FilterBlockTransactionCount(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodGetBlockReceipts):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			return responseBody
		}
		return FilterBlockReceipts(responseBody, addrs)
	}
	return responseBody
}

func rewriteToFullTxObjects(originalBody []byte, params []any) []byte {
	var newParams []any
	if len(params) >= 2 {
		newParams = make([]any, len(params))
		copy(newParams, params)
		newParams[1] = true
	} else {
		newParams = make([]any, 2)
		if len(params) == 1 {
			newParams[0] = params[0]
		}
		newParams[1] = true
	}

	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  []any           `json:"params"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(originalBody, &env); err != nil {
		return nil
	}
	env.Params = newParams
	b, err := json.Marshal(env)
	if err != nil {
		return nil
	}
	return b
}

func rewriteToGetBlock(originalBody []byte, newMethod string, params []any) []byte {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  []any           `json:"params"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(originalBody, &env); err != nil {
		return nil
	}
	env.Method = newMethod
	
	newParams := make([]any, 0, 2)
	if len(params) > 0 {
		newParams = append(newParams, params[0])
	} else {
		newParams = append(newParams, "latest")
	}
	newParams = append(newParams, true)

	env.Params = newParams
	b, err := json.Marshal(env)
	if err != nil {
		return nil
	}
	return b
}

// autoRegisterFactoryDeploy registers a contract after a successful CREATE3 factory deploy.
// This runs asynchronously to avoid blocking the response.
func (p *JSONRPCProcessor) autoRegisterFactoryDeploy(ctx context.Context, info *rbac.FactoryDeployInfo, responseBody []byte) {
	// Parse the response to check if it was successful (has tx hash)
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &rpcResp); err != nil {
		return // Can't parse response, skip
	}

	// If there's an error or no result, the tx failed
	if rpcResp.Error != nil || rpcResp.Result == "" {
		return
	}

	// The tx was submitted successfully - register the contract
	// Note: We register immediately since CREATE3 addresses are deterministic
	// The contract will exist at this address once the tx is mined
	store := p.rbacAccessCtrl.Store()

	// Check if already registered as a contract
	existing, err := store.GetContractByAddress(ctx, info.OrgID, info.TargetAddress)
	if err == nil && existing != nil {
		return // Already registered
	}

	// Create the contract entry
	now := time.Now()
	contract := &rbac.Contract{
		ID:         uuid.New().String(),
		OrgID:      info.OrgID,
		Address:    strings.ToLower(info.TargetAddress),
		Name:       fmt.Sprintf("CREATE3 Deploy %s", info.TargetAddress[:10]),
		DeployedAt: &now,
		Metadata: map[string]interface{}{
			"factory":     info.FactoryAddr,
			"salt":        info.Salt,
			"auto_registered": true,
		},
	}

	if err := store.CreateContract(ctx, contract); err != nil {
		// Log error but don't fail the request - the preregistered address still works
		// The contract can be manually registered later if needed
		return
	}
}

// validateWithTracing performs runtime trace validation for eth_sendTransaction.
// Returns the list of CREATE/CREATE2 targets discovered during tracing (may be nil),
// and a ProcessError if validation fails.
func (p *JSONRPCProcessor) validateWithTracing(ctx context.Context, req *ProcessRequest, targetAddr string) ([]rbac.CreateTarget, *ProcessError) {
	// Skip if tracing is not configured
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		return nil, nil
	}

	// Only trace eth_sendTransaction (state-changing calls)
	if req.Method != "eth_sendTransaction" {
		return nil, nil
	}

	// Skip contract deployments (no target address) - deployment validation is separate
	if targetAddr == "" {
		return nil, nil
	}

	// Get user info early for tiered validation
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user for trace validation",
		}
	}

	// Get user's org memberships
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user memberships for trace validation",
		}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// SECURITY: We only skip tracing for the CREATE3 factory, not for general org-owned contracts.
	//
	// Why NOT skip for org-owned contracts:
	// An org-owned contract could accept arbitrary calldata and make external calls to
	// other orgs' contracts, violating cross-org isolation. Example:
	//   User → OrgA_Contract.attack(OrgB_Address) → OrgB_Contract  ❌ VIOLATION
	//
	// Why skip for factory:
	// The CREATE3 factory is a known, audited contract with deterministic behavior.
	// It only does CREATE2/CREATE internally (no arbitrary external calls), and
	// factory calls are already validated by factory_call_validator in RBAC CheckAccess.
	if p.runtimeTracer.IsTieredEnabled() {
		normalizedTarget := strings.ToLower(strings.TrimSpace(targetAddr))

		for orgID := range userOrgIDs {
			// Only skip tracing for the org's CREATE3 factory
			org, err := p.rbacAccessCtrl.Store().GetOrganization(ctx, orgID)
			if err == nil && org != nil {
				factoryAddr := rbac.GetOrgFactoryAddress(org)
				if factoryAddr != "" && strings.ToLower(factoryAddr) == normalizedTarget {
					// Target is org's factory - skip tracing
					// Factory behavior is deterministic and already validated
					return nil, nil
				}
			}
		}
	}

	// Extract transaction parameters for tracing
	from, to, data, value := extractTxParams(req.Params)
	if to == "" {
		return nil, nil // Deployment - skip (handled by bytecode validation)
	}

	// Only skip tracing for simple value transfers to EOAs.
	// Contracts can execute receive()/fallback() which may make cross-org calls.
	if isSimpleValueTransfer(data) {
		hasCode, err := p.runtimeTracer.HasCode(ctx, to)
		if err != nil {
			// Fail closed - if we can't check, trace anyway
			// (fall through to tracing below)
		} else if !hasCode {
			return nil, nil // EOA - safe to skip tracing
		}
		// Contract with empty calldata - must trace (receive/fallback could make calls)
	}

	// Perform the trace
	traceResult, err := p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	if err != nil {
		// Trace failed - log and deny for safety
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("runtime trace failed: %v", err),
		}
	}

	if traceResult == nil {
		// Fail closed: if tracing was expected but returned no result, deny
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "runtime trace returned no result",
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("trace validation error: %v", err),
		}
	}

	if !validationResult.Allowed {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("cross-org call denied: %s", validationResult.Reason),
		}
	}

	return validationResult.CreateTargets, nil
}

// checkCompliance runs travel rule compliance checks if the checker is configured.
// Called from both eth_sendTransaction and eth_sendRawTransaction paths.
// Returns nil if compliance passes or is disabled, or a ProcessResult with an error.
func (p *JSONRPCProcessor) checkCompliance(ctx context.Context, req *ProcessRequest, orgID, userID, from, to, data, value string) *ProcessResult {
	if p.complianceChecker == nil {
		return nil
	}

	compStart := time.Now()
	compResult, compErr := p.complianceChecker.Check(ctx, &compliance.CheckRequest{
		OrgID:         orgID,
		UserID:        userID,
		From:          from,
		To:            to,
		Data:          data,
		Value:         value,
		CorrelationID: req.CorrelationID,
	})
	if p.metrics != nil {
		p.metrics.ComplianceCheckDuration.WithLabelValues().Observe(time.Since(compStart).Seconds())
	}
	if compErr != nil {
		if p.metrics != nil {
			p.metrics.ComplianceDecisionsTotal.WithLabelValues("error").Inc()
		}
		p.logAccess(ctx, req, http.StatusInternalServerError)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusInternalServerError,
				Message:    "compliance check failed: " + compErr.Error(),
			},
		}
	}
	if !compResult.Allowed {
		if p.metrics != nil {
			p.metrics.ComplianceDecisionsTotal.WithLabelValues("denied").Inc()
		}
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "compliance denied: " + compResult.Reason,
			},
		}
	}
	if p.metrics != nil {
		p.metrics.ComplianceDecisionsTotal.WithLabelValues("allowed").Inc()
	}

	return nil
}

// isSimpleValueTransfer returns true if the transaction has no calldata.
// Note: this alone is NOT sufficient to skip tracing - the caller must also
// verify the target is an EOA (not a contract) via eth_getCode, because
// contracts can execute receive()/fallback() which may make cross-org calls.
func isSimpleValueTransfer(data string) bool {
	// Normalize and check for empty calldata
	data = strings.TrimSpace(data)
	return data == "" || data == "0x" || data == "0X"
}

// processRawTransaction handles eth_sendRawTransaction with RLP decoding.
// This method is ONLY allowed when runtime tracing is enabled, because we need
// to trace all call targets to validate cross-org isolation.
func (p *JSONRPCProcessor) processRawTransaction(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	// eth_sendRawTransaction requires runtime tracing for security
	if p.runtimeTracer == nil || !p.runtimeTracer.IsEnabled() {
		p.recordRPCOutcome(req.Method, "tracing_required", start)
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "eth_sendRawTransaction requires runtime tracing to be enabled for security validation",
			},
		}
	}

	// Extract and decode the raw transaction
	rawTxHex, err := extractRawTxHex(req.Params)
	if err != nil {
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid raw transaction: " + err.Error(),
			},
		}
	}

	// Decode RLP to get transaction details
	from, to, data, value, txNonce, err := decodeRawTransaction(rawTxHex)
	if err != nil {
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "failed to decode raw transaction: " + err.Error(),
			},
		}
	}

	// Determine the operation type and required claims
	var requiredClaims []rbac.Claim
	isDeployment := to == ""
	if isDeployment {
		requiredClaims = []rbac.Claim{rbac.ClaimDeploy}
	} else {
		requiredClaims = []rbac.Claim{rbac.ClaimWrite}
	}

	// Build RBAC access check request
	// For raw transactions, we use eth_sendTransaction for classification
	// since the operation is equivalent
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           "eth_sendTransaction", // Use sendTransaction for RBAC classification
		Params:           buildTxParams(from, to, data, value),
		TargetAddress:    to,
		FunctionSelector: extractSelector(data),
		RequiredClaims:   requiredClaims,
	}

	// Check RBAC access
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		slog.Error("RBAC access check failed", "method", req.Method, "error", err)
		p.recordRPCOutcome(req.Method, "error", start)
		p.logAccess(ctx, req, http.StatusInternalServerError, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}

	if !result.Allowed {
		realStatus := http.StatusForbidden
		if result.AuthRequired {
			realStatus = http.StatusUnauthorized
		}
		slog.Info("RBAC access denied", "method", req.Method, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "reason", result.Reason)
		p.recordRPCOutcome(req.Method, "rbac_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, realStatus, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}
	p.recordRBACDecision("allowed")

	// Runtime tracing validation (always runs for raw transactions)
	var runtimeCreateTargets []rbac.CreateTarget
	if to != "" {
		skipTrace := false
		if isSimpleValueTransfer(data) {
			// Only skip tracing for simple value transfers to EOAs.
			// Contracts can execute receive()/fallback() which may make cross-org calls.
			hasCode, err := p.runtimeTracer.HasCode(ctx, to)
			if err == nil && !hasCode {
				skipTrace = true // EOA - safe to skip tracing
			}
			// If err or hasCode: fall through to tracing
		}
		if !skipTrace {
			rawRuntimeCreateTargets, traceErr := p.validateRawTxWithTracing(ctx, req, from, to, data, value)
			if traceErr != nil {
				p.logAccess(ctx, req, http.StatusForbidden)
				return &ProcessResult{
					Error: traceErr,
				}
			}
			runtimeCreateTargets = rawRuntimeCreateTargets
		}
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if compErr := p.checkCompliance(ctx, req, result.OrgID, result.UserID, from, to, data, value); compErr != nil {
		return compErr
	}

	// Check rate limits
	allowed, rateLimitReason := p.rateLimiter.CheckAndIncrement(req.UserID, result.RateLimitRPS, result.RateLimitDaily)
	if !allowed {
		p.recordRPCOutcome(req.Method, "rate_limited", start)
		if p.metrics != nil {
			p.metrics.RateLimitHitsTotal.WithLabelValues("rpc").Inc()
		}
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    rateLimitReason,
			},
		}
	}

	// Pre-register plain CREATE for raw transactions (nonce is embedded in the signed tx).
	var rawTxPlainCreateAddr string
	if isDeployment {
		fromAddr := gethcommon.HexToAddress(from)
		contractAddr := gethcrypto.CreateAddress(fromAddr, txNonce)
		addrStr := strings.ToLower(contractAddr.Hex())
		note := fmt.Sprintf("plain CREATE pending (raw tx): deployer=%s org=%s", result.UserID, result.OrgID)
		if preErr := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, result.OrgID, addrStr, note); preErr != nil {
			slog.Warn("plain CREATE pre-registration failed for raw tx", "error", preErr)
		} else {
			rawTxPlainCreateAddr = addrStr
		}
	}

	// Pre-register runtime CREATE/CREATE2 addresses discovered during trace validation.
	var runtimeCreateAddrs []string
	if len(runtimeCreateTargets) > 0 {
		runtimeCreateAddrs = p.preRegisterRuntimeCreates(ctx, result.OrgID, runtimeCreateTargets)
	}

	// Forward the original raw transaction to node
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.Forward(req.Body)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}
	if err != nil {
		p.recordRPCOutcome(req.Method, "forward_error", start)
		// Clean up pre-registration on forward failure.
		if rawTxPlainCreateAddr != "" {
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), rawTxPlainCreateAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", rawTxPlainCreateAddr, "error", delErr)
			}
		}
		for _, addr := range runtimeCreateAddrs {
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), addr); delErr != nil {
				slog.Warn("failed to clean up runtime create pre-registration on forward error", "address", addr, "error", delErr)
			}
		}
		p.logAccess(ctx, req, http.StatusBadGateway)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadGateway,
				Message:    fmt.Sprintf("failed to forward request: %v", err),
			},
		}
	}

	// Handle plain CREATE pre-registration tracking/cleanup.
	if rawTxPlainCreateAddr != "" {
		var rpcResp struct {
			Result string `json:"result"`
			Error  *struct{ Message string `json:"message"` } `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp) == nil &&
			rpcResp.Error == nil &&
			rpcResp.Result != ""

		if nodeAccepted {
			// Track and start background receipt polling.
			p.rbacAccessCtrl.TrackPlainCreateDeployment(rpcResp.Result, result.OrgID, result.UserID, rawTxPlainCreateAddr)
			p.pollAndFinalizePlainCreate(rpcResp.Result, rawTxPlainCreateAddr, result.OrgID, result.UserID)
		} else {
			// Node rejected the tx — delete the pre-registration immediately.
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), rawTxPlainCreateAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", rawTxPlainCreateAddr, "error", delErr)
			}
		}
	}

	// Handle runtime CREATE/CREATE2 tracking/cleanup.
	if len(runtimeCreateAddrs) > 0 {
		var rpcResp2 struct {
			Result string                         `json:"result"`
			Error  *struct{ Message string `json:"message"` } `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp2) == nil &&
			rpcResp2.Error == nil &&
			rpcResp2.Result != ""

		if nodeAccepted {
			go p.pollAndFinalizeRuntimeCreates(rpcResp2.Result, runtimeCreateAddrs, result.OrgID, result.UserID)
		} else {
			// Node rejected — clean up pre-registrations
			for _, addr := range runtimeCreateAddrs {
				if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
					context.Background(), addr); delErr != nil {
					slog.Warn("failed to clean up runtime create pre-registration", "address", addr, "error", delErr)
				}
			}
		}
	}

	// System-link the sender's ETH address to their DID.
	if statusCode == http.StatusOK && from != "" && req.UserID != "" {
		if err := p.rbacAccessCtrl.Store().SystemLinkEthAddress(ctx, req.UserID, from); err != nil {
			slog.Warn("failed to system-link eth address", "user", req.UserID, "address", from, "error", err)
		}
	}

	// Log successful access
	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

// processDebugTrace handles debug_traceTransaction and debug_traceCall safely.
// It uses TraceValidator to guarantee 100% org isolation before returning trace output.
func (p *JSONRPCProcessor) processDebugTrace(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "runtime tracing is not supported or enabled on this proxy",
			},
		}
	}

	// 1. Must have Deploy or Admin claim globally
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		p.logAccess(ctx, req, http.StatusUnauthorized)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusUnauthorized, Message: "failed to get user"}}
	}

	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		p.logAccess(ctx, req, http.StatusInternalServerError)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusInternalServerError, Message: "failed to get memberships"}}
	}

	if !p.userHasDeployClaim(ctx, memberships) {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "tracing requires deploy or admin claims"}}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// 2. Perform the internal trace
	var traceResult *tracer.TraceResult
	var traceErr error

	if req.Method == "debug_traceTransaction" {
		if len(req.Params) == 0 {
			return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusBadRequest, Message: "missing transaction hash"}}
		}
		txHash, ok := req.Params[0].(string)
		if !ok {
			return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusBadRequest, Message: "invalid transaction hash"}}
		}
		traceResult, traceErr = p.runtimeTracer.TraceMinedTransaction(ctx, txHash)
	} else if req.Method == "debug_traceCall" {
		from, to, data, value := extractTxParams(req.Params)
		traceResult, traceErr = p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	}

	if traceErr != nil {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: fmt.Sprintf("trace execution failed: %v", traceErr)}}
	}
	if traceResult == nil {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "trace returned no result"}}
	}

	// 3. Validate the trace tree strictly
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, true)
	if err != nil {
		p.logAccess(ctx, req, http.StatusInternalServerError)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusInternalServerError, Message: "trace validation error"}}
	}

	// THE GATE: Ensure no cross-org leaks occur.
	if !validationResult.Allowed {
		p.logAccess(ctx, req, http.StatusForbidden)
		// We purposefully do NOT return the trace output here. We return the Access Denied reason.
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: fmt.Sprintf("cross-org trace denied: %s", validationResult.Reason)}}
	}

	// 4. Rate Limit (Tracing is expensive, hard limit to low RPS)
	rps, daily := 1, 100
	allowed, rateLimitReason := p.rateLimiter.CheckAndIncrement(req.UserID, &rps, &daily)
	if !allowed {
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: rateLimitReason}}
	}

	// 5. Validated & Safe! Forward the exact request to the upstream node to fetch the raw requested trace format
	// (Since we used internal tracers like callTracer, but they might want struct logs or memory dumps)
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.Forward(req.Body)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}
	if err != nil {
		p.logAccess(ctx, req, http.StatusBadGateway)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusBadGateway, Message: "failed to forward trace request"}}
	}

	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)
	
	// Return the raw response exactly as it came from the node
	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

// validateRawTxWithTracing performs runtime trace validation for raw transactions.
// Returns the list of CREATE/CREATE2 targets discovered during tracing (may be nil),
// and a ProcessError if validation fails.
func (p *JSONRPCProcessor) validateRawTxWithTracing(ctx context.Context, req *ProcessRequest, from, to, data, value string) ([]rbac.CreateTarget, *ProcessError) {
	// Get user info for trace validation
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user for trace validation",
		}
	}

	// Get user's org memberships
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user memberships for trace validation",
		}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// Perform the trace
	traceResult, err := p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("runtime trace failed: %v", err),
		}
	}

	if traceResult == nil {
		// Fail closed: if tracing was expected but returned no result, deny
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "runtime trace returned no result",
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("trace validation error: %v", err),
		}
	}

	if !validationResult.Allowed {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("cross-org call denied: %s", validationResult.Reason),
		}
	}

	return validationResult.CreateTargets, nil
}

// userHasDeployClaim checks whether any of the user's memberships grant the deploy claim.
func (p *JSONRPCProcessor) userHasDeployClaim(ctx context.Context, memberships []*rbac.MembershipWithDetails) bool {
	for _, m := range memberships {
		if m.Membership == nil {
			continue
		}
		access, err := p.rbacAccessCtrl.Store().GetGroupAccess(ctx, m.Membership.GroupID)
		if err != nil || access == nil {
			continue
		}
		for _, c := range access.Claims {
			if c == rbac.ClaimDeploy || c == rbac.ClaimAdmin {
				return true
			}
		}
	}
	return false
}

// extractRawTxHex extracts the raw transaction hex from eth_sendRawTransaction params.
func extractRawTxHex(params []any) (string, error) {
	if len(params) == 0 {
		return "", fmt.Errorf("missing transaction parameter")
	}

	rawTxHex, ok := params[0].(string)
	if !ok {
		return "", fmt.Errorf("transaction parameter must be a string")
	}

	return rawTxHex, nil
}

// decodeRawTransaction decodes an RLP-encoded transaction and extracts its fields.
// Returns from (recovered from signature), to, data, value as hex strings, and the nonce.
func decodeRawTransaction(rawTxHex string) (from, to, data, value string, nonce uint64, err error) {
	// Remove 0x prefix
	rawTxHex = strings.TrimPrefix(rawTxHex, "0x")
	rawTxHex = strings.TrimPrefix(rawTxHex, "0X")

	// Decode hex to bytes
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("invalid hex: %w", err)
	}

	// Decode RLP transaction
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTxBytes); err != nil {
		return "", "", "", "", 0, fmt.Errorf("failed to decode transaction: %w", err)
	}

	nonce = tx.Nonce()

	// Extract 'to' address (nil for contract creation)
	if tx.To() != nil {
		to = tx.To().Hex()
	}

	// Extract data
	if len(tx.Data()) > 0 {
		data = "0x" + hex.EncodeToString(tx.Data())
	}

	// Extract value
	if tx.Value() != nil && tx.Value().Sign() > 0 {
		value = "0x" + tx.Value().Text(16)
	}

	// Recover 'from' address from signature
	signer := types.LatestSignerForChainID(tx.ChainId())
	fromAddr, err := types.Sender(signer, tx)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("failed to recover sender: %w", err)
	}
	from = fromAddr.Hex()

	return from, to, data, value, nonce, nil
}

// buildTxParams builds transaction params for RBAC checking.
func buildTxParams(from, to, data, value string) []any {
	txObj := map[string]any{
		"from": from,
	}
	if to != "" {
		txObj["to"] = to
	}
	if data != "" {
		txObj["data"] = data
	}
	if value != "" {
		txObj["value"] = value
	}
	return []any{txObj}
}

// extractSelector extracts the function selector from calldata.
func extractSelector(data string) string {
	if len(data) < 10 {
		return ""
	}
	return strings.ToLower(data[:10])
}

// extractTxParams extracts transaction parameters from eth_sendTransaction params.
func extractTxParams(params []any) (from, to, data, value string) {
	if len(params) == 0 {
		return
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return
	}

	if f, ok := txObj["from"].(string); ok {
		from = f
	}
	if t, ok := txObj["to"].(string); ok {
		to = t
	}
	if d, ok := txObj["data"].(string); ok {
		data = d
	} else if d, ok := txObj["input"].(string); ok {
		data = d
	}
	if v, ok := txObj["value"].(string); ok {
		value = v
	}

	return
}

// extractNonceFromTxParams reads the "nonce" field from eth_sendTransaction params.
// Returns (nonce, true) if present and parseable, (0, false) otherwise.
func extractNonceFromTxParams(params []any) (uint64, bool) {
	if len(params) == 0 {
		return 0, false
	}
	txObj, ok := params[0].(map[string]any)
	if !ok {
		return 0, false
	}
	nonceVal, exists := txObj["nonce"]
	if !exists {
		return 0, false
	}
	nonceStr, ok := nonceVal.(string)
	if !ok {
		return 0, false
	}
	hexStr := strings.TrimPrefix(nonceStr, "0x")
	n, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// getNonceFromNode fetches the pending transaction count (nonce) for an address from the node.
func (p *JSONRPCProcessor) getNonceFromNode(from string) (uint64, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionCount",
		"params":  []any{from, "pending"},
		"id":      1,
	})
	if err != nil {
		return 0, err
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		return 0, fmt.Errorf("get nonce: %w", err)
	}
	var resp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return 0, fmt.Errorf("parse nonce response: %w", err)
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("nonce RPC error: %s", resp.Error.Message)
	}
	hexStr := strings.TrimPrefix(resp.Result, "0x")
	nonce, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse nonce hex %q: %w", resp.Result, err)
	}
	return nonce, nil
}

// preRegisterPlainCreate computes the deterministic CREATE address from (from, nonce)
// and inserts it into preregistered_addresses for the deployer's org.
// This closes the cross-org race window before the tx is forwarded.
// Returns the pre-registered address (lowercase, 0x-prefixed).
func (p *JSONRPCProcessor) preRegisterPlainCreate(ctx context.Context, orgID, userID string, params []any) (string, error) {
	from, _, _, _ := extractTxParams(params)
	if from == "" {
		return "", fmt.Errorf("plain CREATE: missing 'from' in tx params")
	}

	// Get nonce: prefer explicit value from params, fall back to node query.
	nonce, hasNonce := extractNonceFromTxParams(params)
	if !hasNonce {
		var err error
		nonce, err = p.getNonceFromNode(from)
		if err != nil {
			return "", fmt.Errorf("plain CREATE nonce: %w", err)
		}
	}

	// Compute the deterministic CREATE address: keccak256(rlp([from, nonce]))[12:]
	contractAddr := gethcrypto.CreateAddress(gethcommon.HexToAddress(from), nonce)
	addrStr := strings.ToLower(contractAddr.Hex())

	note := fmt.Sprintf("plain CREATE pending: deployer=%s org=%s", userID, orgID)
	if err := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, orgID, addrStr, note); err != nil {
		return "", fmt.Errorf("pre-register plain CREATE: %w", err)
	}

	return addrStr, nil
}

// pollAndFinalizePlainCreate polls for the receipt of a plain CREATE deployment
// and calls NotifyDeploymentMined to finalize or clean up the pre-registration.
// Runs in a goroutine; gives up after maxAttempts with exponential backoff.
func (p *JSONRPCProcessor) pollAndFinalizePlainCreate(txHash, preRegisteredAddr, orgID, deployerUserID string) {
	const maxAttempts = 12
	const baseDelay = 2 * time.Second

	go func() {
		ctx := context.Background()
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if attempt > 0 {
				delay := baseDelay * time.Duration(1<<uint(attempt-1))
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				time.Sleep(delay)
			}

			contractAddr, err := p.getTransactionReceipt(txHash)
			if err != nil {
				// Receipt not available yet — retry.
				continue
			}

			// Receipt obtained (contractAddr is "" on revert).
			if err := p.rbacAccessCtrl.NotifyDeploymentMined(ctx, txHash, contractAddr); err != nil {
				// Revert or finalization issue — logged inside NotifyDeploymentMined.
				slog.Warn("plain CREATE finalization failed", "tx_hash", txHash, "error", err)
			}
			return
		}

		// Exhausted retries — clean up the pre-registration to avoid orphaned rows.
		slog.Warn("plain CREATE: exhausted receipt retries, cleaning up pre-registration", "tx_hash", txHash, "address", preRegisteredAddr)
		if err := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
			context.Background(), preRegisteredAddr); err != nil {
			slog.Error("plain CREATE: failed to clean up pre-registration", "address", preRegisteredAddr, "error", err)
		}
	}()
}

// getTransactionReceipt fetches the receipt for a tx and returns the contract address.
// Returns ("", nil) if the receipt shows a revert.
// Returns ("", error) if the receipt is not yet available (tx not mined).
func (p *JSONRPCProcessor) getTransactionReceipt(txHash string) (string, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []any{txHash},
		"id":      1,
	})
	if err != nil {
		return "", err
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		return "", fmt.Errorf("receipt RPC: %w", err)
	}
	var resp struct {
		Result *struct {
			Status          string `json:"status"`          // "0x1" = success, "0x0" = fail
			ContractAddress string `json:"contractAddress"` // set for deployments
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse receipt: %w", err)
	}
	if resp.Error != nil {
		return "", fmt.Errorf("receipt RPC error: %s", resp.Error.Message)
	}
	if resp.Result == nil {
		return "", fmt.Errorf("receipt not yet available")
	}
	// Status "0x0" = revert; return "" so caller knows to clean up.
	if resp.Result.Status == "0x0" {
		return "", nil
	}
	return strings.ToLower(resp.Result.ContractAddress), nil
}

// getTransactionReceiptStatus fetches the receipt for a tx and returns whether it succeeded.
// Returns (true, nil) if the receipt shows success (status "0x1").
// Returns (false, nil) if the receipt shows a revert (status "0x0").
// Returns (false, error) if the receipt is not yet available (tx not mined).
func (p *JSONRPCProcessor) getTransactionReceiptStatus(txHash string) (bool, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []any{txHash},
		"id":      1,
	})
	if err != nil {
		return false, err
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		return false, fmt.Errorf("receipt RPC: %w", err)
	}
	var resp struct {
		Result *struct {
			Status string `json:"status"` // "0x1" = success, "0x0" = fail
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false, fmt.Errorf("parse receipt: %w", err)
	}
	if resp.Error != nil {
		return false, fmt.Errorf("receipt RPC error: %s", resp.Error.Message)
	}
	if resp.Result == nil {
		return false, fmt.Errorf("receipt not yet available")
	}
	return resp.Result.Status == "0x1", nil
}

// preRegisterRuntimeCreates pre-registers addresses from runtime CREATE/CREATE2 operations
// discovered during trace validation. Returns the list of successfully pre-registered addresses.
func (p *JSONRPCProcessor) preRegisterRuntimeCreates(ctx context.Context, orgID string, targets []rbac.CreateTarget) []string {
	var addrs []string
	for _, t := range targets {
		addr := strings.ToLower(t.Address)
		note := fmt.Sprintf("runtime %s from %s", t.Type, t.From)
		if err := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, orgID, addr, note); err != nil {
			slog.Warn("runtime create pre-registration failed", "address", addr, "type", t.Type, "error", err)
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// pollAndFinalizeRuntimeCreates polls for the receipt of a transaction that contains
// runtime CREATE/CREATE2 operations, then reconciles pre-registered addresses with
// the actual addresses from the mined trace.
func (p *JSONRPCProcessor) pollAndFinalizeRuntimeCreates(txHash string, preRegAddrs []string, orgID, userID string) {
	ctx := context.Background()
	const maxAttempts = 12
	const baseDelay = 2 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			time.Sleep(delay)
		}

		// Get receipt status (not contractAddress — runtime creates are internal)
		success, err := p.getTransactionReceiptStatus(txHash)
		if err != nil {
			continue // Not mined yet
		}

		if !success {
			// Transaction reverted — clean up all pre-registrations
			for _, addr := range preRegAddrs {
				_ = p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(ctx, addr)
			}
			slog.Info("runtime creates cleaned up (tx reverted)", "tx_hash", txHash)
			return
		}

		// Transaction succeeded — trace to get actual created addresses
		actualAddrs := make(map[string]bool)
		if p.runtimeTracer != nil {
			traceResult, traceErr := p.runtimeTracer.TraceMinedTransaction(ctx, txHash)
			if traceErr == nil && traceResult != nil {
				for _, target := range traceResult.CallTargets {
					if target.Type == "CREATE" || target.Type == "CREATE2" {
						actualAddrs[strings.ToLower(target.To)] = true
					}
				}
			} else {
				slog.Warn("failed to trace mined tx for runtime creates", "tx_hash", txHash, "error", traceErr)
				// Fall back: assume pre-registered addresses are correct
				for _, addr := range preRegAddrs {
					actualAddrs[addr] = true
				}
			}
		} else {
			// No tracer available — assume pre-registered addresses are correct
			for _, addr := range preRegAddrs {
				actualAddrs[addr] = true
			}
		}

		// Reconcile: finalize actual addresses, clean up stale pre-registrations
		preRegSet := make(map[string]bool)
		for _, addr := range preRegAddrs {
			preRegSet[addr] = true
		}

		// Finalize addresses that were actually created
		now := time.Now()
		for addr := range actualAddrs {
			// Use NotifyDeploymentMined for addresses we tracked via the pending tracker
			if preRegSet[addr] {
				// Track it so NotifyDeploymentMined can find it
				p.rbacAccessCtrl.TrackPlainCreateDeployment(txHash, orgID, userID, addr)
				if err := p.rbacAccessCtrl.NotifyDeploymentMined(ctx, txHash, addr); err != nil {
					slog.Warn("runtime create finalization via NotifyDeploymentMined failed",
						"address", addr, "tx_hash", txHash, "error", err)
				}
			} else {
				// Address wasn't pre-registered (diverged from simulation) — register directly
				slog.Info("runtime create: registering diverged address", "address", addr, "tx_hash", txHash, "org_id", orgID)
				contract := &rbac.Contract{
					ID:      uuid.New().String(),
					OrgID:   orgID,
					Address: addr,
					Name:    fmt.Sprintf("Contract %s", addr[:10]),
					Metadata: map[string]any{
						"auto_registered": true,
						"via":             "runtime_create",
						"tx_hash":         txHash,
					},
				}
				if userID != "" {
					contract.DeployedByUserID = &userID
				}
				contract.DeployedAt = &now
				if createErr := p.rbacAccessCtrl.Store().CreateContract(ctx, contract); createErr != nil {
					slog.Warn("failed to register diverged runtime create", "address", addr, "error", createErr)
				} else if userID != "" {
					deployerDID := ""
					if u, uErr := p.rbacAccessCtrl.Store().GetUser(ctx, userID); uErr == nil && u != nil {
						deployerDID = u.ExternalID
					}
					if gErr := p.rbacAccessCtrl.Store().CreateDeployerAutoGrants(ctx, orgID, contract.ID, userID, deployerDID); gErr != nil {
						slog.Warn("failed to create deployer auto-grants for runtime create", "address", addr, "error", gErr)
					}
				}
			}
		}

		// Clean up pre-registrations that weren't actually created (simulation diverged)
		for _, addr := range preRegAddrs {
			if !actualAddrs[addr] {
				slog.Info("runtime create: cleaning up diverged pre-registration", "address", addr, "tx_hash", txHash)
				_ = p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(ctx, addr)
			}
		}

		slog.Info("runtime creates finalized", "tx_hash", txHash, "pre_registered", len(preRegAddrs), "actual", len(actualAddrs))
		return
	}

	// Exhausted retries — clean up orphaned pre-registrations
	slog.Warn("runtime create finalization exhausted retries", "tx_hash", txHash)
	for _, addr := range preRegAddrs {
		_ = p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(ctx, addr)
	}
}

// recordRPCOutcome records RPC request count and duration metrics.
// The method is normalized to a known allowlist to prevent label cardinality bombs.
func (p *JSONRPCProcessor) recordRPCOutcome(method, outcome string, start time.Time) {
	if p.metrics == nil {
		return
	}
	safeMethod := metrics.NormalizeRPCMethod(method)
	p.metrics.RPCRequestsTotal.WithLabelValues(safeMethod, outcome).Inc()
	p.metrics.RPCRequestDuration.WithLabelValues(safeMethod).Observe(time.Since(start).Seconds())
}

// recordRBACDecision records an RBAC decision metric.
func (p *JSONRPCProcessor) recordRBACDecision(decision string) {
	if p.metrics == nil {
		return
	}
	p.metrics.RBACDecisionsTotal.WithLabelValues(decision).Inc()
}
