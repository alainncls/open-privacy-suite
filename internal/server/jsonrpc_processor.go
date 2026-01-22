package server

import (
	"context"
	"fmt"
	"net/http"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
)

// JSONRPCProcessor handles the business logic for JSON-RPC requests.
// It separates concerns from HTTP handling, making the logic testable
// and reusable.
type JSONRPCProcessor struct {
	rbacAccessCtrl *rbac.AccessController
	rateLimiter    *RateLimiter
	proxy          *proxy.Proxy
	accessLogger   AccessLogger
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
	rateLimiter *RateLimiter,
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
// 2. Rate limiting
// 3. Forwarding to the target node
func (p *JSONRPCProcessor) Process(ctx context.Context, req *ProcessRequest) *ProcessResult {
	// Build RBAC access check request
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(req.Method, req.Params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}

	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		Method:           req.Method,
		Params:           req.Params,
		TargetAddress:    rbac.GetTargetAddress(req.Method, req.Params),
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

	// Log successful access
	p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}
