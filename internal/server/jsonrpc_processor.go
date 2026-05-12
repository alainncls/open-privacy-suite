package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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

	// Per-tx visibility store (visibleTo feature)
	txVisibilityStore rbac.TxVisibilityProvider

	// Circuit breaker + concurrency limiter (replaces rate limiter for authenticated users)
	circuitBreaker        *CircuitBreaker
	concurrencyLimiter    *ConcurrencyLimiter
	defaultRPCAPIKey      string
	defaultRPCAPIKeyHeader string // operator-wide header name from RPC_API_KEY_HEADER; empty => proxy.DefaultAPIKeyHeader

	// RD-915: eth_call cross-org tracing.
	// State snapshot held in an atomic.Pointer so the validator's hot
	// path reads it lock-free, and the super-admin toggle endpoint can
	// replace the whole snapshot atomically. The env-derived default is
	// installed once at startup via SetEthCallTracing; runtime overrides
	// from the admin endpoint are in-memory only — a restart re-arms
	// the env value, which is the durable change-management control
	// (RD-915 KD-5, ISO 27001 A.8.32).
	ethCallTracing      atomic.Pointer[ethCallTracingState]
	ethCallTraceTimeout time.Duration // ETH_CALL_TRACE_TIMEOUT — distinct from send-side TraceTimeout.

	// Prometheus metrics
	metrics *metrics.Metrics
}

// ethCallTracingState captures the current value of the eth_call tracing
// knob and the metadata needed to render a GET response from the admin
// endpoint. EnvDefault records the value the env var asked for at startup
// so operators can tell "currently overridden vs back to default" without
// inspecting the env. Source is "env" until the first runtime override.
type ethCallTracingState struct {
	Enabled    bool
	EnvDefault bool
	Source     string    // "env" | "runtime_override"
	ChangedAt  time.Time // zero until first override
	ChangedBy  string    // empty until first override
	Reason     string    // empty until first override
}

// TxVisibilitySaver saves per-tx visibleTo rules. Implemented by db.DB.
type TxVisibilitySaver interface {
	SaveTxVisibility(ctx context.Context, txHash string, visibleToDIDs []string, senderDID, orgID string) error
}

// AccessLogger logs access attempts for auditing.
type AccessLogger interface {
	LogAccess(ctx context.Context, userID, method string, statusCode int, clientIP string) error
}

// EnhancedAccessLogger logs access with correlation ID, params, and returns the entry ID for hash chain.
// responseStatus is nil when it matches statusCode (non-opaque request).
type EnhancedAccessLogger interface {
	LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte, responseStatus *int) (int64, time.Time, error)
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
	cb *CircuitBreaker,
	cl *ConcurrencyLimiter,
	defaultAPIKey string,
) *JSONRPCProcessor {
	p := &JSONRPCProcessor{
		rbacAccessCtrl:      rbacCtrl,
		rateLimiter:         rateLimiter,
		proxy:               proxyClient,
		accessLogger:        logger,
		circuitBreaker:      cb,
		concurrencyLimiter:  cl,
		defaultRPCAPIKey:    defaultAPIKey,
		ethCallTraceTimeout: 5 * time.Second,
	}
	// Wire-level safe-by-default — the server constructor calls
	// SetEthCallTracing(...) right after to install the env-derived
	// value. Until then, tracing is on.
	p.ethCallTracing.Store(&ethCallTracingState{
		Enabled:    true,
		EnvDefault: true,
		Source:     "env",
	})
	return p
}

// SetEthCallTracing installs the env-derived configuration for the RD-915
// eth_call cross-org tracing knobs. `enabled` defaults to true; the env
// var only flips it to false as a documented sev-1 rollback path.
// `timeout` caps how long the proxy waits for the upstream
// debug_traceCall on the eth_call validation path; distinct from the
// send-side TraceTimeout. This wipes any prior runtime override — boot
// always re-arms from env (RD-915 KD-5, ISO 27001 A.8.32).
func (p *JSONRPCProcessor) SetEthCallTracing(enabled bool, timeout time.Duration) {
	p.ethCallTracing.Store(&ethCallTracingState{
		Enabled:    enabled,
		EnvDefault: enabled,
		Source:     "env",
	})
	if timeout > 0 {
		p.ethCallTraceTimeout = timeout
	}
}

// SetEthCallTracingRuntimeOverride records an in-memory toggle from the
// super-admin endpoint. The change is NOT persisted: a restart re-arms
// the env value. `reason` and `who` are required for the audit trail.
// Returns the new snapshot so the handler can echo it in its response.
func (p *JSONRPCProcessor) SetEthCallTracingRuntimeOverride(enabled bool, who, reason string) *ethCallTracingState {
	prev := p.ethCallTracing.Load()
	envDefault := true
	if prev != nil {
		envDefault = prev.EnvDefault
	}
	next := &ethCallTracingState{
		Enabled:    enabled,
		EnvDefault: envDefault,
		Source:     "runtime_override",
		ChangedAt:  time.Now().UTC(),
		ChangedBy:  who,
		Reason:     reason,
	}
	p.ethCallTracing.Store(next)
	return next
}

// EthCallTracingSnapshot returns the current state for the admin GET
// handler. Never returns nil — the constructor seeds a default.
func (p *JSONRPCProcessor) EthCallTracingSnapshot() ethCallTracingState {
	s := p.ethCallTracing.Load()
	if s == nil {
		return ethCallTracingState{Enabled: true, EnvDefault: true, Source: "env"}
	}
	return *s
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

// SetDefaultRPCAPIKeyHeader sets the operator-wide header name used to forward
// the RPC API key (from the RPC_API_KEY_HEADER env var). Empty input means
// "use Authorization / Bearer" — the proxy default.
func (p *JSONRPCProcessor) SetDefaultRPCAPIKeyHeader(name string) {
	p.defaultRPCAPIKeyHeader = name
}

// resolveAPIKeyHeader returns the header name used to forward the upstream
// RPC API key. The header is operator-wide (set via the RPC_API_KEY_HEADER
// env var); there is no per-group override.
func (p *JSONRPCProcessor) resolveAPIKeyHeader() string {
	if p.defaultRPCAPIKeyHeader != "" {
		return p.defaultRPCAPIKeyHeader
	}
	return proxy.DefaultAPIKeyHeader
}

// SetTxVisibilityStore configures the per-tx visibility provider for
// visibleTo feature. When set, the processor resolves visibleTo rules
// from the DB during response filtering and stores them during send.
func (p *JSONRPCProcessor) SetTxVisibilityStore(store rbac.TxVisibilityProvider) {
	p.txVisibilityStore = store
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

		var respStatusPtr *int
		if respStatus != statusCode {
			respStatusPtr = &respStatus
		}
		id, createdAt, err := p.enhancedLogger.LogAccessEnhanced(ctx, req.UserID, req.Method, statusCode, req.ClientIP, req.CorrelationID, params, respStatusPtr)
		if err != nil {
			// Fallback to basic logging
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
			return
		}

		// Compute and store hash chain entry (format version 2)
		// All fields stored in DB and verifiable — request_params is TEXT
		// (not JSONB) to preserve exact bytes for hash chain verification.
		paramsDigest := ""
		if len(params) > 0 {
			paramsDigest = string(params)
		}
		entryContent := fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
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
			event := audit.SIEMEvent{
				Timestamp:     createdAt,
				EventType:     "access",
				CorrelationID: req.CorrelationID,
				ActorID:       req.UserID,
				Action:        req.Method,
				Outcome:       outcome,
				Details:       fmt.Sprintf("decision=%d response=%d", statusCode, respStatus),
				SourceIP:      req.ClientIP,
				EntryHash:     hash,
			}
			// Tag wildcard-resolved methods so SIEM consumers can filter on the
			// passthrough surface independently from explicitly-listed methods.
			if w := rbac.MatchWildcard(req.Method); w != nil {
				event.MatchedVia = "wildcard"
				event.MatchedPrefix = w.Prefix
			}
			p.siemForwarder.Send(event)
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
	cb *CircuitBreaker,
	cl *ConcurrencyLimiter,
	defaultAPIKey string,
) *JSONRPCProcessor {
	return &JSONRPCProcessor{
		rbacAccessCtrl:     rbacCtrl,
		rateLimiter:        rateLimiter,
		proxy:              proxyClient,
		accessLogger:       logger,
		runtimeTracer:      runtimeTracer,
		traceValidator:     traceValidator,
		circuitBreaker:     cb,
		concurrencyLimiter: cl,
		defaultRPCAPIKey:   defaultAPIKey,
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

	// Resolve method alias for access control (e.g. linea_estimateGas → eth_estimateGas).
	// The alias determines which access control rules apply (contract checks, storage tiering, etc.)
	// while the original method name is kept for the RBAC allowlist check and node forwarding.
	accessMethod := rbac.ResolveMethodAlias(req.Method)

	// Build RBAC access check request using the alias for target/selector extraction
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(accessMethod, req.Params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}

	targetAddr := rbac.GetTargetAddress(accessMethod, req.Params)

	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           req.Method,
		AccessMethod:     accessMethod,
		Params:           req.Params,
		TargetAddress:    targetAddr,
		FunctionSelector: rbac.GetFunctionSelector(accessMethod, req.Params),
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
		slog.Info("RBAC access denied", "method", req.Method, "user", req.UserID, "ip", req.ClientIP, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "user", req.UserID, "reason", result.Reason)
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

	// Concurrency gate moves ABOVE the trace path (RD-915 F5). Pre-RD-915
	// fix this sat below the trace, which meant a single JWT could pin N
	// upstream debug_traceCall connections concurrently (N == request rate
	// over the trace's wall-clock window) before any limiter fired. The
	// 5s per-trace timeout caps individual cost; only the limiter caps
	// aggregate. Acquire before trace so the cap covers the trace itself.
	if p.concurrencyLimiter != nil && !p.concurrencyLimiter.TryAcquire(req.UserID) {
		if p.metrics != nil {
			p.metrics.ConcurrencyRejectionsTotal.Inc()
		}
		p.recordRPCOutcome(req.Method, "concurrent_limit", start)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "too many concurrent requests",
			},
		}
	}
	if p.concurrencyLimiter != nil {
		defer p.concurrencyLimiter.Release(req.UserID)
	}

	// Runtime tracing: validate all call targets for eth_sendTransaction
	runtimeCreateTargets, traceErr := p.validateWithTracing(ctx, req, targetAddr)
	if traceErr != nil {
		p.recordRPCOutcome(req.Method, "send_trace_denied", start)
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: traceErr,
		}
	}

	// RD-915: runtime trace eth_call to enforce cross-org isolation on
	// internal calls. Without this the entry-point access check is the
	// only gate, and a same-org wrapper contract can STATICCALL into a
	// foreign-org private contract and bubble up the result. No caching
	// (proxy-pattern contracts can re-target via storage rewrites).
	if ethCallTraceErr := p.validateEthCallWithTracing(ctx, req, targetAddr); ethCallTraceErr != nil {
		p.recordRPCOutcome(req.Method, "eth_call_trace_denied", start)
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: ethCallTraceErr,
		}
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if req.Method == "eth_sendTransaction" {
		from, to, data, value := extractTxParams(req.Params)
		if compErr := p.checkCompliance(ctx, req, result.OrgID, result.UserID, from, to, data, value); compErr != nil {
			return compErr
		}
	}

	// Extract and strip visibleTo from eth_sendTransaction before forwarding.
	// Only accepted on contract calls (tx with data field) — plain ETH transfers
	// have no event logs, so visibleTo is rejected for them.
	var visibleTo []string
	if req.Method == "eth_sendTransaction" {
		visibleTo = extractAndStripVisibleTo(req)
		if len(visibleTo) > visibleToMaxSize {
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusBadRequest,
					Message:    fmt.Sprintf("visibleTo list exceeds maximum size of %d entries", visibleToMaxSize),
				},
			}
		}
		if len(visibleTo) > 0 {
			_, to, data, _ := extractTxParams(req.Params)
			if isSimpleValueTransfer(data) || to == "" || to == "0x" {
				return &ProcessResult{
					Error: &ProcessError{
						StatusCode: http.StatusBadRequest,
						Message:    "visibleTo is only supported for contract calls that emit event logs",
					},
				}
			}
		}
	}

	// Concurrency limit acquired earlier (above the trace path) — see
	// the block following recordRBACDecision("allowed").

	// Resolve API key (group-specific or default)
	apiKey := result.RPCAPIKey
	if apiKey == "" {
		apiKey = p.defaultRPCAPIKey
	}
	apiKeyHeader := p.resolveAPIKeyHeader()

	// Check circuit breaker
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(apiKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
		}
		p.recordRPCOutcome(req.Method, "circuit_open", start)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "upstream rate limited, retry in 1s",
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
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(forwardBody, apiKeyHeader, apiKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}

	// Circuit breaker: track upstream 429s
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
			}
			p.circuitBreaker.Trip(apiKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(apiKey)
		}
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

	// Store visibleTo rule if provided. The tx hash comes from the node response.
	// Non-fatal: the tx is already sent, so we log errors but don't fail the response.
	//
	// M7 (security audit): if SaveTxVisibility errors here, the tx is
	// already on-chain and the listed DIDs never get visibility on a
	// tx the sender intended to share. Retry-on-next-request is not a
	// thing for a one-shot mutation. A proper fix needs an outbox
	// table + background reconciler (`pending_tx_visibility`) — left
	// as a follow-up ticket. For now: escalate to slog.Error with the
	// recipient list so operators can manually replay; surface a
	// header so the client knows the side-channel failed.
	if len(visibleTo) > 0 && statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			if saver, ok := p.txVisibilityStore.(TxVisibilitySaver); ok {
				if err := saver.SaveTxVisibility(ctx, txHash, visibleTo, req.UserID, result.OrgID); err != nil {
					slog.Error("visibleTo save failed; tx is on-chain but recipients won't see it",
						"tx", txHash, "recipients", len(visibleTo), "sender", req.UserID, "org", result.OrgID, "error", err)
				}
			}
		}
	}

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

// viewerUUID extracts the internal user UUID from an AccessCheckResult,
// returning "" if the result is nil. The empty string is the safe input
// for viewerAdminContracts (which short-circuits to an empty admin map),
// matching the visibleTo-only fallback path where the viewer has no
// CheckAccess result but is still a legitimate visibleTo recipient.
func viewerUUID(result *rbac.AccessCheckResult) string {
	if result == nil {
		return ""
	}
	return result.UserID
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
	// Resolve method alias so chain-specific methods (e.g. linea_getTransactionExclusionStatusV1)
	// inherit the same response filtering as their standard equivalents.
	m := rbac.ResolveMethodAlias(req.Method)
	switch {
	case strings.EqualFold(m, rbac.MethodGetTransactionByHash):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			addrs = nil // DB error — proceed with nil addrs; visibleTo + admin bypass still apply
		}
		// Org-scoped admin bypass: compute whether the viewer has the
		// admin claim in the tx's `to` contract's OWNING org specifically
		// (not merged across all orgs the viewer belongs to). See
		// viewerAdminContracts doc for why.
		// IMPORTANT: viewerAdminContracts takes the internal user UUID
		// (result.UserID), NOT the JWT DID — internally it queries
		// user_memberships.user_id, which is the UUID FK. Passing the
		// DID silently returns no matches and the bypass never fires.
		// `result` may be nil on the visibleTo-only fallback path
		// (the visibleTo recipient may not have a CheckAccess result);
		// guard accordingly — empty userID makes viewerAdminContracts
		// short-circuit to an empty map, the right answer when the
		// viewer can't be admin-resolved.
		contractAddrs := extractContractAddressesFromResponse(responseBody)
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), contractAddrs)
		isAdminOnTo := false
		for addr := range adminMap {
			if adminMap[addr] {
				isAdminOnTo = true
				break // tx-by-hash response has at most one `to`
			}
		}
		filtered := FilterTransactionByHash(responseBody, addrs, isAdminOnTo)
		// If participant + admin check returned null, check visibleTo as fallback
		if isNullResult(filtered) && p.isResponseTxVisibleTo(ctx, req.UserID, responseBody) {
			return responseBody
		}
		return filtered

	case strings.EqualFold(m, rbac.MethodGetTransactionReceipt):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			addrs = nil // DB error — proceed with nil addrs, visCtx handles visibleTo
		}
		perms := p.resolvePermsForFilter(ctx, result)
		visCtx := p.buildTxVisibilityContext(ctx, req.UserID, responseBody)
		// Org-scoped admin map covers both the receipt-envelope bypass
		// (for receipt.to) and the per-log admin bypass (for each log's
		// emitting contract). Filter handles the lookup.
		// Pass the internal user UUID (result.UserID), not the JWT DID.
		// viewerUUID() guards against nil result (visibleTo-only path).
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), extractContractAddressesFromResponse(responseBody))
		return FilterReceiptLogsWithEventRules(responseBody, addrs, perms, p.contractABIProvider(ctx), visCtx, adminMap)

	case strings.EqualFold(m, rbac.MethodGetLogs):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			// DB error — fail closed
			id := rpcResponseID(responseBody)
			return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":[]}`)
		}
		// Note: empty addrs is OK — user may have no linked ETH addresses but
		// still has visibleTo entries. The filter handles this via visCtx.
		perms := p.resolvePermsForFilter(ctx, result)
		visCtx := p.buildTxVisibilityContext(ctx, req.UserID, responseBody)
		// Org-scoped admin-bypass map, indexed by each log's emitting
		// contract. Takes the internal user UUID (result.UserID), not
		// the JWT DID — viewerAdminContracts queries user_memberships
		// by UUID FK. viewerUUID() guards against nil result.
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), extractContractAddressesFromResponse(responseBody))
		return FilterLogsWithEventRules(responseBody, addrs, perms, p.contractABIProvider(ctx), visCtx, adminMap)

	case strings.EqualFold(m, rbac.MethodGetTransactionByBlockHashAndIndex),
		strings.EqualFold(m, rbac.MethodGetTransactionByBlockNumberAndIndex):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			addrs = nil // DB error — proceed with nil addrs; visibleTo + admin bypass still apply
		}
		// Pass the internal user UUID (result.UserID), not the JWT DID.
		// viewerUUID() guards against nil result.
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), extractContractAddressesFromResponse(responseBody))
		isAdminOnTo := false
		for _, v := range adminMap {
			if v {
				isAdminOnTo = true
				break
			}
		}
		filtered := FilterTransactionByHash(responseBody, addrs, isAdminOnTo)
		// If participant + admin check returned null, check visibleTo as fallback
		if isNullResult(filtered) && p.isResponseTxVisibleTo(ctx, req.UserID, responseBody) {
			return responseBody
		}
		return filtered

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
		slog.Warn("send trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
		}
	}

	if traceResult == nil {
		slog.Warn("send trace: nil result",
			slog.String("user", req.UserID), slog.String("to", to))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy)
	if err != nil {
		slog.Warn("send trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    sendTraceValidatorError,
		}
	}

	if !validationResult.Allowed {
		slog.Info("send trace: denial",
			slog.String("user", req.UserID), slog.String("to", to))
		slog.Debug("send trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyMessage(validationResult.Reason),
		}
	}

	return validationResult.CreateTargets, nil
}

// User-facing deny messages for eth_call runtime tracing (RD-915 KD-3).
// Constants — never interpolate upstream node errors into the response,
// and never echo a non-precompile contract address (an attacker who didn't
// otherwise know that address exists in another org now does — same shape
// as RD-916). Diagnostic detail goes to slog.Debug + access_logs.
const (
	ethCallDenyCrossOrg       = "call denied: cross-org access not permitted"
	ethCallDenyDepthExceeded  = "call denied: trace depth exceeded; not provable as same-org"
	ethCallDenyTracerError    = "call denied: tracing temporarily unavailable"
	ethCallDenyInvalidRequest = "call denied: invalid request shape"
)

// User-facing deny messages for the send-side trace path (validateWithTracing
// and processRawTransaction). Same KD-3 rationale as the eth_call constants:
// the upstream error and the validator's DeniedTarget never reach the
// response body. Pre-RD-915 these sites %v'd the upstream error and Reason
// into the deny string; that's the same disclosure surface RD-916 + RD-915
// close on the read side.
const (
	sendTraceDenyCrossOrg     = "transaction denied: cross-org access not permitted"
	sendTraceDenyDeployClaim  = "transaction denied: runtime contract creation requires the deploy claim"
	sendTraceDenyTracerError  = "transaction denied: tracing temporarily unavailable"
	sendTraceValidatorError   = "transaction denied: trace validation unavailable"
)

// sendTraceDenyMessage maps a TraceValidationResult to the appropriate
// send-side constant message, keeping the response body opaque.
func sendTraceDenyMessage(reason string) string {
	if reason == "runtime contract creation requires deploy claim" {
		return sendTraceDenyDeployClaim
	}
	return sendTraceDenyCrossOrg
}

// validateEthCallWithTracing enforces cross-org isolation on every internal
// CALL/STATICCALL/DELEGATECALL frame produced by an eth_call (RD-915). Today
// the entry-point address is the only gate: an attacker can wrap a foreign-
// org private contract with a same-org facade and bubble up state through
// the return value. This closes the read-side of that gap. The send-side
// equivalent is validateWithTracing.
//
// Differences from the send path that matter:
//   - No caching. Proxy patterns (EIP-1967, Diamond, Beacon, transparent)
//     can re-target their internal calls by rewriting a storage slot, so
//     a (from,to,data,value) cache yields stale "allow" decisions after
//     a cross-org upgrade. We use TraceTransactionUncached. Regression net:
//     internal/server/eth_call_tracing_integration_test.go
//     (TestEthCallTracing_ProxyImplementationFlip exercises the same
//     (from,to,data,value) twice with different upstream traces and
//     confirms the second decision is fresh, plus
//     TestTraceTransactionUncached_BypassesCachedHit at the tracer layer).
//   - `from` is rebound to the JWT-bound EOA. Sends pin msg.sender via the
//     unlocked key; reads do not, and accepting user-supplied `from` lets
//     an attacker take an "if (msg.sender == orgB-router)" branch they
//     would never reach as themselves. Reject mismatched user-supplied
//     `from` with 400 invalid request rather than silently rebinding,
//     because silent rebinding would mask spoofing attempts in the logs.
//   - Distinct timeout (default 5s) caps individual trace duration. Note
//     this is NOT a quota cap — the concurrency limiter is acquired at
//     line ~460, AFTER this function runs, so a single JWT can issue many
//     concurrent eth_calls that each pin a tracer goroutine for up to the
//     timeout. Per-user gating before the tracer is tracked in RD-923.
//   - Distinct deny messages (the four constants above) — never %v the
//     upstream error and never echo the denied contract address.
//
// Returns nil to allow the eth_call to be forwarded; non-nil to deny.
func (p *JSONRPCProcessor) validateEthCallWithTracing(ctx context.Context, req *ProcessRequest, targetAddr string) *ProcessError {
	// Lock-free atomic load of the (env + runtime-override) state. The
	// super-admin endpoint can replace this between any two invocations;
	// each call reads a self-consistent snapshot.
	if state := p.ethCallTracing.Load(); state == nil || !state.Enabled {
		return nil
	}
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		return nil
	}
	// Match via ResolveMethodAlias so chain-specific equivalents that the
	// operator has explicitly aliased to eth_call (e.g. linea_call) also go
	// through tracing. The send-side equivalent gate is method-literal because
	// eth_sendTransaction has no aliases today; the read side does (RD-915
	// design doc, "Open questions" — "Allowlist of methods that go through
	// eth_call tracing"). Wildcard-passthrough methods without an explicit
	// alias stay at the operator's discretion per RD-911 — opting into
	// wildcards opts out of RBAC, and re-tracing on top of that would defeat
	// the wildcard semantic.
	if rbac.ResolveMethodAlias(req.Method) != "eth_call" {
		return nil
	}
	if targetAddr == "" {
		// No target — nothing to trace. The entry-point access check
		// would have already rejected this if RBAC required a target.
		return nil
	}

	from, to, data, value := extractTxParams(req.Params)

	// Extract the block param (params[1]) the same way the upstream
	// eth_call will receive it; if the trace runs at a different block
	// than the forwarded call, the trace at "latest" can allow a call
	// that returns historical cross-org state from a since-flipped proxy
	// — a time-shifted variant of the proxy-flip attack closed by the
	// uncached path. extractEthCallBlockParam validates the shape and
	// returns the value as the JSON-RPC layer should see it.
	blockParam, blockErr := extractEthCallBlockParam(req.Params)
	if blockErr != nil {
		return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest}
	}

	// Input validation BEFORE tracing: malformed addresses cannot be
	// allowed to burn a concurrency slot or emit a metric labeled with
	// junk. gethcommon.IsHexAddress accepts mixed-case checksummed and
	// uppercase forms.
	if to == "" || !gethcommon.IsHexAddress(to) {
		return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest}
	}
	if from != "" && !gethcommon.IsHexAddress(from) {
		return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest}
	}

	// Resolve the JWT-bound user identity and rebind `from`. The JWT
	// already passed CheckAccess, so user lookup must succeed; if it
	// doesn't, fail closed.
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		slog.Warn("eth_call trace: user lookup failed",
			slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError}
	}

	// Discover the user's linked EOAs. Any user-supplied `from` must
	// equal one of them. Empty `from` is allowed — the upstream node
	// will treat it as the zero address. Rejecting a mismatch (rather
	// than silently rebinding) preserves the audit trail of spoof
	// attempts: the access_log row records the attempted `from` and
	// the deny.
	userAddrs, addrErr := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
	if addrErr != nil {
		slog.Warn("eth_call trace: linked-address lookup failed",
			slog.String("user", req.UserID), slog.Any("err", addrErr))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError}
	}
	if from != "" {
		fromLC := strings.ToLower(from)
		match := false
		for _, a := range userAddrs {
			if strings.ToLower(a) == fromLC {
				match = true
				break
			}
		}
		if !match {
			slog.Info("eth_call trace: user-supplied from rejected (not in linked addresses)",
				slog.String("user", req.UserID), slog.String("from", from))
			return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest}
		}
	}

	// Org memberships → for ValidateTrace's cross-org check.
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		slog.Warn("eth_call trace: membership lookup failed",
			slog.String("user_uuid", user.ID), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError}
	}
	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// Per-call timeout. Distinct from the 30s send-side TraceTimeout.
	traceCtx, cancel := context.WithTimeout(ctx, p.ethCallTraceTimeout)
	defer cancel()

	// Uncached trace — see function-level docstring. blockParam mirrors
	// the param the forwarded eth_call will use so trace and actual call
	// run against the same chain state.
	traceResult, err := p.runtimeTracer.TraceTransactionUncached(traceCtx, from, to, data, value, blockParam)
	if err != nil {
		// Distinguish depth-exceeded from upstream-node errors. Both
		// are 403 from the user's POV (tracing-incomplete = deny), but
		// we surface a distinct message so triage can tell deep
		// recursion apart from a node hiccup. Never %v the err.
		if errors.Is(err, tracer.ErrTraceDepthExceeded) {
			slog.Info("eth_call trace: depth exceeded",
				slog.String("user", req.UserID), slog.String("to", to))
			return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyDepthExceeded}
		}
		slog.Warn("eth_call trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError}
	}
	if traceResult == nil {
		// Tracer is enabled but returned nil — fail closed. This is
		// the same posture as the send path (line ~910).
		slog.Warn("eth_call trace: nil result", slog.String("user", req.UserID), slog.String("to", to))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError}
	}

	// userHasDeploy is irrelevant for read-only validation but the
	// validator's signature requires it; the deploy-claim branch only
	// affects CREATE-frame handling, which eth_call cannot produce.
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy)
	if err != nil {
		slog.Warn("eth_call trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusInternalServerError, Message: ethCallDenyTracerError}
	}
	if !validationResult.Allowed {
		// Diagnostic detail (which contract triggered the deny, and the
		// kind of denial) goes to slog only — never to the response body.
		// DenialKind lets audit / SIEM distinguish "touched another org"
		// from "touched an unregistered address" without parsing slog text.
		kind := string(validationResult.DenialKind)
		slog.Info("eth_call trace: denial",
			slog.String("user", req.UserID),
			slog.String("to", to),
			slog.String("kind", kind))
		slog.Debug("eth_call trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("kind", kind),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyCrossOrg}
	}

	return nil
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
		// M1: don't echo the raw compliance error to the client — it can
		// carry token addresses, threshold values, sanction text, and
		// upstream price-service detail. Keep the verbose message in
		// slog; surface a generic 5xx to the caller.
		slog.Error("compliance check failed", "method", req.Method, "err", compErr)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusInternalServerError,
				Message:    "compliance check failed",
			},
		}
	}
	if !compResult.Allowed {
		if p.metrics != nil {
			p.metrics.ComplianceDecisionsTotal.WithLabelValues("denied").Inc()
		}
		p.logAccess(ctx, req, http.StatusForbidden)
		// M1: map the deny reason to a finite enum-style category before
		// echoing. Pre-fix, "no price configured for token 0x..." in the
		// response confirmed existence of a private contract — same
		// disclosure shape RD-916/917 closed elsewhere. Keep the full
		// reason in compliance_log + slog only.
		slog.Info("compliance denied", "method", req.Method, "reason", compResult.Reason)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "compliance denied: " + sanitizeComplianceReason(compResult.Reason),
			},
		}
	}
	if p.metrics != nil {
		p.metrics.ComplianceDecisionsTotal.WithLabelValues("allowed").Inc()
	}

	return nil
}

// sanitizeComplianceReason maps a compliance deny reason to a finite
// enum-style category safe to echo to the JSON-RPC client. The full
// reason (which may contain token addresses, sanction text, threshold
// values, or upstream price-service detail) is preserved in
// compliance_log + slog only.
//
// Categories chosen to be operationally useful without revealing any
// per-tenant data. See security audit M1.
func sanitizeComplianceReason(in string) string {
	lower := strings.ToLower(in)
	switch {
	case strings.Contains(lower, "sanction"):
		return "sanctioned address"
	case strings.Contains(lower, "no price") || strings.Contains(lower, "price not") || strings.Contains(lower, "unknown_price"):
		return "transaction value cannot be computed"
	case strings.Contains(lower, "threshold"):
		return "transaction exceeds threshold"
	case strings.Contains(lower, "record") && strings.Contains(lower, "required"):
		return "travel-rule record required"
	case strings.Contains(lower, "originator"):
		return "originator validation failed"
	case strings.Contains(lower, "currency"):
		return "currency configuration error"
	default:
		return "transaction blocked by compliance policy"
	}
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

	// Determine the operation type and required claims.
	// Only deployments need a claim gate; write access is controlled by the
	// method allowlist (eth_sendTransaction must be in allowed_methods).
	var requiredClaims []rbac.Claim
	isDeployment := to == ""
	if isDeployment {
		requiredClaims = []rbac.Claim{rbac.ClaimDeploy}
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
		slog.Info("RBAC access denied", "method", req.Method, "user", req.UserID, "ip", req.ClientIP, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "user", req.UserID, "reason", result.Reason)
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

	// Concurrency gate moves ABOVE the trace path (RD-915 F5). Mirrors
	// the Process() path. Acquire before any trace so the cap covers
	// the trace itself, not just downstream forwarding.
	if p.concurrencyLimiter != nil && !p.concurrencyLimiter.TryAcquire(req.UserID) {
		if p.metrics != nil {
			p.metrics.ConcurrencyRejectionsTotal.Inc()
		}
		p.recordRPCOutcome(req.Method, "concurrent_limit", start)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "too many concurrent requests",
			},
		}
	}
	if p.concurrencyLimiter != nil {
		defer p.concurrencyLimiter.Release(req.UserID)
	}

	// Runtime tracing validation (always runs for raw transactions
	// when there's a target address).
	//
	// M10 (security audit, open follow-up): raw-tx DEPLOYMENTS (`to ==
	// ""`) currently skip the runtime tracer entirely. The deploy
	// validator runs bytecode-level checks at deploy time, but if the
	// CREATE constructor itself makes internal CREATE/CREATE2/CALL
	// frames into other orgs, those are not validated here. The threat
	// is narrow (only relevant for factory-pattern constructors
	// reaching across orgs at deploy time) and runtime tracing for
	// pure deployments would need a debug_traceCall path with an
	// empty `to`; tracked as a follow-up ticket. Leaving the gap
	// explicit so a future code review doesn't lose sight of it.
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
				p.recordRPCOutcome(req.Method, "send_trace_denied", start)
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

	// Extract and strip visibleTo from second param (if present) before forwarding.
	// Only accepted on contract calls — plain transfers have no event logs.
	var rawTxVisibleTo []string
	rawTxVisibleTo = extractAndStripRawTxVisibleTo(req)
	if len(rawTxVisibleTo) > visibleToMaxSize {
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    fmt.Sprintf("visibleTo list exceeds maximum size of %d entries", visibleToMaxSize),
			},
		}
	}
	if len(rawTxVisibleTo) > 0 {
		if isSimpleValueTransfer(data) || to == "" {
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusBadRequest,
					Message:    "visibleTo is only supported for contract calls that emit event logs",
				},
			}
		}
	}

	// Concurrency limit acquired earlier (above the trace path) — see
	// the block following recordRBACDecision("allowed") in this function.

	// Resolve API key (group-specific or default)
	apiKey := result.RPCAPIKey
	if apiKey == "" {
		apiKey = p.defaultRPCAPIKey
	}
	apiKeyHeader := p.resolveAPIKeyHeader()

	// Check circuit breaker
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(apiKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
		}
		p.recordRPCOutcome(req.Method, "circuit_open", start)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "upstream rate limited, retry in 1s",
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
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(req.Body, apiKeyHeader, apiKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}

	// Circuit breaker: track upstream 429s
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
			}
			p.circuitBreaker.Trip(apiKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(apiKey)
		}
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

	// Store visibleTo rule if provided (raw tx). Non-fatal.
	if len(rawTxVisibleTo) > 0 && statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			if saver, ok := p.txVisibilityStore.(TxVisibilitySaver); ok {
				if err := saver.SaveTxVisibility(ctx, txHash, rawTxVisibleTo, req.UserID, result.OrgID); err != nil {
					slog.Error("failed to save visibleTo for raw tx", "tx", txHash, "error", err)
				}
			}
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
	traceAPIKey := p.defaultRPCAPIKey
	traceAPIKeyHeader := p.resolveAPIKeyHeader()
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(traceAPIKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(traceAPIKey)).Inc()
		}
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: "upstream rate limited, retry in 1s"}}
	}
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(req.Body, traceAPIKeyHeader, traceAPIKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(traceAPIKey)).Inc()
			}
			p.circuitBreaker.Trip(traceAPIKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(traceAPIKey)
		}
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
		slog.Warn("raw send trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
		}
	}

	if traceResult == nil {
		slog.Warn("raw send trace: nil result",
			slog.String("user", req.UserID), slog.String("to", to))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy)
	if err != nil {
		slog.Warn("raw send trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    sendTraceValidatorError,
		}
	}

	if !validationResult.Allowed {
		slog.Info("raw send trace: denial",
			slog.String("user", req.UserID), slog.String("to", to))
		slog.Debug("raw send trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyMessage(validationResult.Reason),
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

// extractEthCallBlockParam returns the block parameter from an eth_call
// param list (the second positional arg), validated to a shape geth's
// debug_traceCall will accept. Returns nil when omitted — the tracer
// falls back to "latest" in that case. The supported shapes are:
//
//   - string: a block tag ("latest", "earliest", "pending", "safe",
//     "finalized") or a 0x-prefixed hex block number ("0x1234").
//   - EIP-1898 object: {"blockNumber": "0x.."} or
//     {"blockHash": "0x..", "requireCanonical": bool}.
//
// Returns an error for any other shape — passing unknown JSON through to
// the upstream would let an attacker craft a malformed-but-different
// param that geth interprets as "latest" while the trace path receives
// something else, undoing the symmetry F2 is meant to establish.
func extractEthCallBlockParam(params []any) (any, error) {
	if len(params) < 2 {
		return nil, nil
	}
	if params[1] == nil {
		return nil, nil
	}
	switch v := params[1].(type) {
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		if s == "" {
			return nil, nil
		}
		switch s {
		case "latest", "earliest", "pending", "safe", "finalized":
			return s, nil
		}
		// Hex block number — must be 0x-prefixed and parse as hex.
		if strings.HasPrefix(s, "0x") && len(s) > 2 {
			for _, c := range s[2:] {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return nil, fmt.Errorf("eth_call block tag: not hex")
				}
			}
			return s, nil
		}
		return nil, fmt.Errorf("eth_call block tag: unknown")
	case map[string]any:
		// EIP-1898 — accept blockNumber XOR blockHash, both hex.
		bn, hasNumber := v["blockNumber"]
		bh, hasHash := v["blockHash"]
		if !hasNumber && !hasHash {
			return nil, fmt.Errorf("eth_call block object: missing blockNumber/blockHash")
		}
		if hasNumber && hasHash {
			return nil, fmt.Errorf("eth_call block object: cannot set both blockNumber and blockHash")
		}
		check := func(val any) error {
			s, ok := val.(string)
			if !ok {
				return fmt.Errorf("not a string")
			}
			s = strings.ToLower(strings.TrimSpace(s))
			if !strings.HasPrefix(s, "0x") || len(s) <= 2 {
				return fmt.Errorf("not 0x-hex")
			}
			for _, c := range s[2:] {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return fmt.Errorf("non-hex")
				}
			}
			return nil
		}
		if hasNumber {
			if err := check(bn); err != nil {
				return nil, fmt.Errorf("eth_call blockNumber: %w", err)
			}
		}
		if hasHash {
			if err := check(bh); err != nil {
				return nil, fmt.Errorf("eth_call blockHash: %w", err)
			}
		}
		return v, nil
	default:
		return nil, fmt.Errorf("eth_call block param: unsupported type %T", params[1])
	}
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
					if gErr := p.rbacAccessCtrl.Store().GrantContractToDeployerGroup(ctx, orgID, contract.ID, userID); gErr != nil {
						slog.Warn("failed to grant contract to deployer group for runtime create", "address", addr, "error", gErr)
					} else {
						// Drop the deployer's cached permissions so the next call to the
						// newly-registered contract re-resolves and sees the new grant.
						if invErr := p.rbacAccessCtrl.InvalidateUser(ctx, userID); invErr != nil {
							slog.Warn("failed to invalidate deployer cache after runtime create grant", "user_id", userID, "error", invErr)
						}
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

// visibleToMaxSize bounds the per-tx visibleTo recipient list. Lists
// larger than this are rejected at sendTransaction with HTTP 400.
// Bound chosen for two reasons:
//
//  1. Storage: every entry persists in tx_visible_to indefinitely.
//     32 entries × ~50 bytes/DID × tx volume keeps growth predictable.
//  2. RD-874: under the unlock semantic each entry is an effective
//     ACL grant for that tx's events. Capping at 32 limits the blast
//     radius of an abusive tx sender listing every DID they can
//     enumerate.
//
// Operators with legitimate >32 recipient use cases should use a
// dedicated group + grant instead of stuffing visibleTo.
const visibleToMaxSize = 32

// extractAndStripVisibleTo extracts the visibleTo field from the tx object
// in eth_sendTransaction params[0], removes it so it's not forwarded to the node,
// and rebuilds req.Body. Returns the DID list (nil if not present).
func extractAndStripVisibleTo(req *ProcessRequest) []string {
	if len(req.Params) == 0 {
		return nil
	}
	txObj, ok := req.Params[0].(map[string]any)
	if !ok {
		return nil
	}
	raw, exists := txObj["visibleTo"]
	if !exists {
		return nil
	}
	// Remove from params so it's not forwarded.
	delete(txObj, "visibleTo")

	// Rebuild request body without the field.
	req.Body = rebuildRequestBody(req.Body, req.Params)

	// Parse the DID list, validate each, and dedupe (L2).
	switch v := raw.(type) {
	case []any:
		dids := make([]string, 0, len(v))
		seen := make(map[string]struct{}, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok || !isValidDID(s) {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			dids = append(dids, s)
		}
		if len(dids) > 0 {
			return dids
		}
	case []string:
		dids := make([]string, 0, len(v))
		seen := make(map[string]struct{}, len(v))
		for _, s := range v {
			if !isValidDID(s) {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			dids = append(dids, s)
		}
		if len(dids) > 0 {
			return dids
		}
	}
	return nil
}

// isValidDID validates the visibleTo DID format. L2 (security audit):
// pre-fix the raw string was stored verbatim, so garbage/spam entries
// bloated tx_visible_to and slowed every GetVisibleTxHashesForDID
// lookup. Now: must start with "did:", contain a method and method-
// specific identifier, total length ≤ 240, all chars in the iden3 /
// W3C-DID safe alphabet.
func isValidDID(s string) bool {
	if len(s) < len("did:x:y") || len(s) > 240 {
		return false
	}
	if !strings.HasPrefix(s, "did:") {
		return false
	}
	// Require at least one ':' after "did:" (method + ID).
	rest := s[4:]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 || colon == len(rest)-1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == ':' || ch == '-' || ch == '_' || ch == '.':
		default:
			return false
		}
	}
	return true
}

// extractAndStripRawTxVisibleTo extracts visibleTo from the second param
// of eth_sendRawTransaction: {"method": "eth_sendRawTransaction", "params": ["0xf86c...", {"visibleTo": ["did:..."]}]}
// Strips the second param from req.Params and req.Body.
func extractAndStripRawTxVisibleTo(req *ProcessRequest) []string {
	if len(req.Params) < 2 {
		return nil
	}
	opts, ok := req.Params[1].(map[string]any)
	if !ok {
		return nil
	}
	raw, exists := opts["visibleTo"]
	if !exists {
		return nil
	}

	// Strip the second param entirely (only the raw tx hex goes to the node).
	req.Params = req.Params[:1]
	req.Body = rebuildRequestBody(req.Body, req.Params)

	switch v := raw.(type) {
	case []any:
		dids := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				dids = append(dids, s)
			}
		}
		if len(dids) > 0 {
			return dids
		}
	case []string:
		if len(v) > 0 {
			return v
		}
	}
	return nil
}

// rebuildRequestBody reconstructs the JSON-RPC request body from the modified params.
func rebuildRequestBody(originalBody []byte, params []any) []byte {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  []any           `json:"params"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(originalBody, &env); err != nil {
		return originalBody // can't rebuild, pass through
	}
	env.Params = params
	rebuilt, err := json.Marshal(env)
	if err != nil {
		return originalBody
	}
	return rebuilt
}

// extractTxHashFromResult extracts the tx hash from a JSON-RPC response result field.
// Used after eth_sendTransaction / eth_sendRawTransaction to get the hash for
// visibleTo storage.
func extractTxHashFromResult(responseBody []byte) string {
	var resp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return ""
	}
	if resp.Error != nil || resp.Result == "" {
		return ""
	}
	return resp.Result
}

// maskAPIKey returns a masked version of an API key for safe use in logs and
// metrics labels. Shows only the last 4 characters prefixed with "****".
// Returns "" for empty keys, "****" for keys shorter than 4 characters.
func maskAPIKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) < 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}
