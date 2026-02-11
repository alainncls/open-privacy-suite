package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"

	"privacy-proxy/internal/compliance"
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
}

// AccessLogger logs access attempts for auditing.
type AccessLogger interface {
	LogAccess(ctx context.Context, userID, method string, statusCode int, clientIP string) error
}

// ProcessRequest represents a validated JSON-RPC request ready for processing.
type ProcessRequest struct {
	UserID   string
	OrgID    string // Optional: specify which org to use (for users with multiple memberships)
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

// SetComplianceChecker sets the compliance checker for travel rule enforcement.
func (p *JSONRPCProcessor) SetComplianceChecker(checker *compliance.Checker) {
	p.complianceChecker = checker
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
	// Handle eth_sendRawTransaction specially - requires runtime tracing
	if req.Method == "eth_sendRawTransaction" {
		return p.processRawTransaction(ctx, req)
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

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if p.complianceChecker != nil && (req.Method == "eth_sendTransaction") {
		from, to, data, value := extractTxParams(req.Params)
		compResult, compErr := p.complianceChecker.Check(ctx, &compliance.CheckRequest{
			OrgID:  result.OrgID,
			UserID: result.UserID,
			From:   from,
			To:     to,
			Data:   data,
			Value:  value,
		})
		if compErr != nil {
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusInternalServerError, req.ClientIP)
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusInternalServerError,
					Message:    "compliance check failed: " + compErr.Error(),
				},
			}
		}
		if !compResult.Allowed {
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusForbidden, req.ClientIP)
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusForbidden,
					Message:    "compliance denied: " + compResult.Reason,
				},
			}
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
					return nil
				}
			}
		}
	}

	// Extract transaction parameters for tracing
	from, to, data, value := extractTxParams(req.Params)
	if to == "" {
		return nil // Deployment - skip (handled by bytecode validation)
	}

	// Only skip tracing for simple value transfers to EOAs.
	// Contracts can execute receive()/fallback() which may make cross-org calls.
	if isSimpleValueTransfer(data) {
		hasCode, err := p.runtimeTracer.HasCode(ctx, to)
		if err != nil {
			// Fail closed - if we can't check, trace anyway
			// (fall through to tracing below)
		} else if !hasCode {
			return nil // EOA - safe to skip tracing
		}
		// Contract with empty calldata - must trace (receive/fallback could make calls)
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
		// Fail closed: if tracing was expected but returned no result, deny
		return &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "runtime trace returned no result",
		}
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
	// eth_sendRawTransaction requires runtime tracing for security
	if p.runtimeTracer == nil || !p.runtimeTracer.IsEnabled() {
		p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusForbidden, req.ClientIP)
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
	from, to, data, value, err := decodeRawTransaction(rawTxHex)
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

	// Runtime tracing validation (always runs for raw transactions)
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
			traceErr := p.validateRawTxWithTracing(ctx, req, from, to, data, value)
			if traceErr != nil {
				p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusForbidden, req.ClientIP)
				return &ProcessResult{
					Error: traceErr,
				}
			}
		}
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if p.complianceChecker != nil {
		compResult, compErr := p.complianceChecker.Check(ctx, &compliance.CheckRequest{
			OrgID:  result.OrgID,
			UserID: result.UserID,
			From:   from,
			To:     to,
			Data:   data,
			Value:  value,
		})
		if compErr != nil {
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusInternalServerError, req.ClientIP)
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusInternalServerError,
					Message:    "compliance check failed: " + compErr.Error(),
				},
			}
		}
		if !compResult.Allowed {
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, http.StatusForbidden, req.ClientIP)
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusForbidden,
					Message:    "compliance denied: " + compResult.Reason,
				},
			}
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

	// Forward the original raw transaction to node
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

	// Log successful access
	p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

// validateRawTxWithTracing performs runtime trace validation for raw transactions.
func (p *JSONRPCProcessor) validateRawTxWithTracing(ctx context.Context, req *ProcessRequest, from, to, data, value string) *ProcessError {
	// Get user info for trace validation
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

	// Perform the trace
	traceResult, err := p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	if err != nil {
		return &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("runtime trace failed: %v", err),
		}
	}

	if traceResult == nil {
		// Fail closed: if tracing was expected but returned no result, deny
		return &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "runtime trace returned no result",
		}
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
// Returns from (recovered from signature), to, data, value as hex strings.
func decodeRawTransaction(rawTxHex string) (from, to, data, value string, err error) {
	// Remove 0x prefix
	rawTxHex = strings.TrimPrefix(rawTxHex, "0x")
	rawTxHex = strings.TrimPrefix(rawTxHex, "0X")

	// Decode hex to bytes
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid hex: %w", err)
	}

	// Decode RLP transaction
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTxBytes); err != nil {
		return "", "", "", "", fmt.Errorf("failed to decode transaction: %w", err)
	}

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
		return "", "", "", "", fmt.Errorf("failed to recover sender: %w", err)
	}
	from = fromAddr.Hex()

	return from, to, data, value, nil
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
