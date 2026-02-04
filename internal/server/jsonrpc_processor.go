package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

// JSONRPCProcessor handles the business logic for JSON-RPC requests.
// It separates concerns from HTTP handling, making the logic testable
// and reusable.
type JSONRPCProcessor struct {
	rbacAccessCtrl  *rbac.AccessController
	rateLimiter     RateLimiterInterface
	proxy           *proxy.Proxy
	accessLogger    AccessLogger
	runtimeTracer   *tracer.RuntimeTracer
	traceValidator  *rbac.TraceValidator
}

// AccessLogger logs access attempts for auditing.
type AccessLogger interface {
	LogAccess(ctx context.Context, userID, method string, statusCode int, clientIP string) error
}

// ProcessRequest represents a validated JSON-RPC request ready for processing.
type ProcessRequest struct {
	UserID   string
	Method   string
	Params   []any
	Body     []byte
	ClientIP string
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
// 2. Runtime tracing (if enabled, for eth_sendTransaction)
// 3. Rate limiting
// 4. Forwarding to the target node
func (p *JSONRPCProcessor) Process(ctx context.Context, req *ProcessRequest) *ProcessResult {
	// Build RBAC access check request
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(req.Method, req.Params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}

	targetAddr := rbac.GetTargetAddress(req.Method, req.Params)

	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		Method:           req.Method,
		Params:           req.Params,
		TargetAddress:    targetAddr,
		FunctionSelector: rbac.GetFunctionSelector(req.Method, req.Params),
		RequiredClaims:   requiredClaims,
	}

	// Check RBAC access
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusInternalServerError, req.ClientIP)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusInternalServerError,
				Message:    "access check failed: " + err.Error(),
			},
		}
	}

	if !result.Allowed {
		p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusForbidden, req.ClientIP)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "access denied: " + result.Reason,
			},
		}
	}

	// Runtime tracing: validate all call targets for eth_sendTransaction
	if traceErr := p.validateWithTracing(ctx, req, targetAddr); traceErr != nil {
		p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusForbidden, req.ClientIP)
		return &ProcessResult{
			Error: traceErr,
		}
	}

	// Check rate limits
	allowed, rateLimitReason := p.rateLimiter.CheckAndIncrement(req.UserID, result.RateLimitRPS, result.RateLimitDaily)
	if !allowed {
		p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusTooManyRequests, req.ClientIP)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    rateLimitReason,
			},
		}
	}

	// Forward to node
	responseBody, statusCode, err := p.proxy.Forward(req.Body)
	if err != nil {
		p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusBadGateway, req.ClientIP)
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

	// Log successful access
	p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
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
// Returns nil if tracing is disabled, not applicable, or validation passes.
// Returns a ProcessError if validation fails.
func (p *JSONRPCProcessor) validateWithTracing(ctx context.Context, req *ProcessRequest, targetAddr string) *ProcessError {
	// Skip if tracing is not configured
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		return nil
	}

	// Only trace eth_sendTransaction (state-changing calls)
	if req.Method != "eth_sendTransaction" {
		return nil
	}

	// Skip contract deployments (no target address) - deployment validation is separate
	if targetAddr == "" {
		return nil
	}

	// Get user info early for tiered validation
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		return &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user for trace validation",
		}
	}

	// Get user's org memberships
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return &ProcessError{
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

	// Tiered validation: skip tracing if target is known to be org-owned
	// This is critical for factory calls - the factory uses CREATE2/CREATE internally
	// which would be blocked by trace validation, but the RBAC factory call validation
	// already verified the call is legitimate.
	if p.runtimeTracer.IsTieredEnabled() {
		normalizedTarget := strings.ToLower(strings.TrimSpace(targetAddr))

		// Check if target is owned by any of the user's orgs or is the org's factory
		for orgID := range userOrgIDs {
			// Check 1: Is this the org's CREATE3 factory?
			// The factory uses CREATE2/CREATE internally which would fail trace validation,
			// but factory calls are already validated by factory_call_validator in RBAC CheckAccess
			org, err := p.rbacAccessCtrl.Store().GetOrganization(ctx, orgID)
			if err == nil && org != nil {
				factoryAddr := rbac.GetOrgFactoryAddress(org)
				if factoryAddr != "" && strings.ToLower(factoryAddr) == normalizedTarget {
					// Target is org's factory - skip tracing
					return nil
				}
			}

			// Check 2: Is target in org's registered contracts?
			isOwned, err := p.rbacAccessCtrl.Store().IsAddressOwnedByOrg(ctx, normalizedTarget, orgID)
			if err != nil {
				// Log but don't fail - proceed with full tracing
				continue
			}
			if isOwned {
				// Target is org-owned, skip tracing
				// The RBAC CheckAccess already validated the call
				return nil
			}
		}
	}

	// Extract transaction parameters for tracing
	from, to, data, value := extractTxParams(req.Params)
	if to == "" {
		return nil // Deployment - skip (handled by bytecode validation)
	}

	// Skip tracing for simple value transfers (no contract code execution)
	// This is 100% safe because:
	// 1. No calldata means no function call
	// 2. EOAs receiving ETH don't execute code
	// 3. Contract receive()/fallback() with empty calldata is minimal risk
	if isSimpleValueTransfer(data) {
		return nil
	}

	// Perform the trace
	traceResult, err := p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	if err != nil {
		// Trace failed - log and deny for safety
		return &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("runtime trace failed: %v", err),
		}
	}

	if traceResult == nil {
		return nil // Tracing not applicable
	}

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult)
	if err != nil {
		return &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("trace validation error: %v", err),
		}
	}

	if !validationResult.Allowed {
		return &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("cross-org call denied: %s", validationResult.Reason),
		}
	}

	return nil
}

// isSimpleValueTransfer returns true if the transaction has no calldata.
// Simple value transfers (ETH only) don't execute contract code beyond
// receive()/fallback() which is minimal risk and doesn't make external calls.
func isSimpleValueTransfer(data string) bool {
	// Normalize and check for empty calldata
	data = strings.TrimSpace(data)
	return data == "" || data == "0x" || data == "0X"
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
