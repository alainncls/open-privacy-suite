package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/ens"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

type Server struct {
	db              *db.DB
	rbacAccessCtrl  *rbac.AccessController
	proxy           *proxy.Proxy
	privadoVerifier PrivadoVerifier
	jwtService      *auth.JWTService
	sessionStore    *auth.SessionStore
	challengeStore  *ChallengeStore
	rateLimiter     *RateLimiter
	config          *config.Config
	ensResolver     *ens.Resolver
}

// DB returns the database instance (for testing)
func (s *Server) DB() *db.DB {
	return s.db
}

// PrivadoVerifier interface for Privado ID operations
type PrivadoVerifier interface {
	CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error)
	CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string) (*protocol.AuthorizationRequestMessage, error)
	VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error)
}

func New(cfg *config.Config) *Server {
	return NewWithVerifier(cfg, nil)
}

// NewWithVerifier creates a new server with an optional PrivadoVerifier
// If verifier is nil, creates a real PrivadoVerifier from config
// This allows injecting a mock verifier for testing
func NewWithVerifier(cfg *config.Config, verifier PrivadoVerifier) *Server {
	database, err := db.New(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}

	// Initialize Privado ID verifier
	var privadoVerifier PrivadoVerifier
	if verifier != nil {
		privadoVerifier = verifier
	} else {
		privadoVerifier, err = auth.NewPrivadoVerifier(cfg.PrivadoRPCURL, cfg.IPFSGateway)
		if err != nil {
			panic(fmt.Errorf("failed to create Privado verifier: %w", err))
		}
	}

	// Initialize JWT service
	// Access tokens: 30 minutes, Refresh tokens: 7 days
	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		cfg.JWTRefreshSecret,
		30*time.Minute, // Access token TTL
		7*24*time.Hour, // Refresh token TTL
	)
	if err != nil {
		panic(fmt.Errorf("failed to create JWT service: %w", err))
	}

	proxySvc := proxy.New(cfg.NodeURL)

	// Initialize RBAC access controller with 5 minute cache TTL
	// Note: Unregistered address handling is now controlled by default_claims in GroupAccess
	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)

	// Initialize session store (10 minute TTL, cleanup every minute)
	sessionStore := auth.NewSessionStore(10*time.Minute, 1*time.Minute)

	// Initialize challenge store for ETH address linking (5 minute TTL, cleanup every minute)
	challengeStore := NewChallengeStore(5*time.Minute, 1*time.Minute)

	// Initialize rate limiter (cleanup every 10 seconds)
	rateLimiter := NewRateLimiter(10 * time.Second)

	// Initialize ENS resolver (optional - may fail if no mainnet RPC available)
	var ensResolver *ens.Resolver
	if cfg.ENSResolverURL != "" {
		ensResolver, err = ens.NewResolver(cfg.ENSResolverURL)
		if err != nil {
			// Log warning but don't fail - ENS resolution is optional
			fmt.Printf("Warning: failed to create ENS resolver: %v\n", err)
		}
	}

	return &Server{
		db:              database,
		rbacAccessCtrl:  rbacAccessCtrl,
		proxy:           proxySvc,
		privadoVerifier: privadoVerifier,
		jwtService:      jwtService,
		sessionStore:    sessionStore,
		challengeStore:  challengeStore,
		rateLimiter:     rateLimiter,
		config:          cfg,
		ensResolver:     ensResolver,
	}
}

func (s *Server) Run(addr string) error {
	router := gin.Default()

	// Trust Docker network proxies (allows X-Forwarded-For to work correctly)
	// This enables localhost detection when accessing from host to Docker container
	// SECURITY: Only requests FROM these IPs can set X-Forwarded-For headers.
	// External attackers cannot spoof X-Forwarded-For because their IP won't be trusted.
	// Trusted proxy IPs that can set X-Forwarded-For headers
	// Includes Docker networks, private networks, and Tailscale CGNAT range
	router.SetTrustedProxies([]string{
		"127.0.0.1",
		"::1",
		"172.16.0.0/12",  // Docker bridge networks
		"192.168.0.0/16", // Docker custom networks / private networks
		"10.0.0.0/8",     // Private networks
		"100.64.0.0/10",  // Tailscale CGNAT range
	})

	// CORS middleware for frontend
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Health check endpoint (no auth required)
	// Support both GET and HEAD for healthchecks (wget --spider uses HEAD)
	healthHandler := func(c *gin.Context) {
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusOK)
		} else {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		}
	}
	router.GET("/health", healthHandler)
	router.HEAD("/health", healthHandler)

	// Authentication endpoints (no auth required)
	// Register at both root level (for direct access) and under /api (for frontend proxy)
	router.POST("/auth/request", s.handleAuthRequest)
	router.POST("/auth/callback", s.handleAuthCallback)
	router.POST("/refresh", s.handleRefresh)
	router.POST("/revoke", s.handleRevoke)

	// Also register under /api for frontend proxy compatibility
	router.POST("/api/auth/request", s.handleAuthRequest)
	router.POST("/api/auth/callback", s.handleAuthCallback)
	router.GET("/api/auth/session/:id/status", s.handleAuthSessionStatus)
	router.POST("/api/refresh", s.handleRefresh)
	router.POST("/api/revoke", s.handleRevoke)

	// Manual verification endpoint (development/testing only)
	if !s.config.IsProduction() {
		router.POST("/auth/verify", s.handleAuthVerify)
		router.POST("/api/auth/verify", s.handleAuthVerify)
	}

	// ETH endpoints under /api for frontend proxy compatibility
	apiEth := router.Group("/api/eth")
	apiEth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	{
		apiEth.POST("/link/challenge", s.handleEthLinkChallenge)
		apiEth.POST("/link/verify", s.handleEthLinkVerify)
		apiEth.GET("/addresses", s.handleGetEthAddresses)
		apiEth.DELETE("/addresses/:address", s.handleDeleteEthAddress)
		apiEth.POST("/addresses/:address/refresh-ens", s.handleRefreshENS)
	}

	// JSON-RPC proxy endpoint - protected by JWT
	router.POST("/", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)

	// ETH address linking endpoints - protected by JWT
	eth := router.Group("/eth")
	eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	{
		eth.POST("/link/challenge", s.handleEthLinkChallenge)
		eth.POST("/link/verify", s.handleEthLinkVerify)
		eth.GET("/addresses", s.handleGetEthAddresses)
		eth.DELETE("/addresses/:address", s.handleDeleteEthAddress)
		eth.POST("/addresses/:address/refresh-ens", s.handleRefreshENS)
	}

	// API endpoints for UI - protected by localhost-only middleware
	api := router.Group("/api")
	api.Use(s.localhostOnlyMiddleware())
	{
		api.GET("/logs", s.getLogs)
		api.GET("/status", s.getStatus)
		api.POST("/test-request", s.handleTestRequest)

		// RBAC endpoints
		s.registerRBACRoutes(api)
	}

	return router.Run(addr)
}

// MaxRequestBodySize is the maximum allowed request body size (1MB).
const MaxRequestBodySize = 1 << 20 // 1MB

func (s *Server) handleJSONRPC(c *gin.Context) {
	// Extract identity from JWT (set by middleware)
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity in context"})
		return
	}

	subjectStr, ok := subject.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid identity in context"})
		return
	}

	// Read request body with size limit to prevent DoS
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, MaxRequestBodySize+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	// Check if body exceeds limit (we read +1 to detect overflow)
	if len(body) > MaxRequestBodySize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
		return
	}

	// Parse method and params from JSON-RPC request
	method, params, err := proxy.ParseRequest(body)
	if err != nil {
		// Check specifically for batch request error
		if err == proxy.ErrBatchRequest {
			c.JSON(http.StatusBadRequest, gin.H{"error": "batch JSON-RPC requests are not supported for security reasons"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON-RPC request: " + err.Error()})
		return
	}

	// Check access via RBAC
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(method, params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   subjectStr,
		Method:           method,
		Params:           params,
		TargetAddress:    rbac.GetTargetAddress(method, params),
		FunctionSelector: rbac.GetFunctionSelector(method, params),
		RequiredClaims:   requiredClaims,
	}
	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), accessReq)
	if err != nil {
		s.db.LogAccess(subjectStr, method, http.StatusInternalServerError, c.ClientIP())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "access check failed: " + err.Error()})
		return
	}
	if !result.Allowed {
		s.db.LogAccess(subjectStr, method, http.StatusForbidden, c.ClientIP())
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied: " + result.Reason})
		return
	}

	// Check rate limits
	allowed, rateLimitReason := s.rateLimiter.CheckAndIncrement(subjectStr, result.RateLimitRPS, result.RateLimitDaily)
	if !allowed {
		s.db.LogAccess(subjectStr, method, http.StatusTooManyRequests, c.ClientIP())
		c.JSON(http.StatusTooManyRequests, gin.H{"error": rateLimitReason})
		return
	}

	// Restore request body for forwarding (it was consumed by io.ReadAll)
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	// Forward to node
	responseBody, statusCode, err := s.proxy.Forward(body)
	if err != nil {
		// Log error
		s.db.LogAccess(subjectStr, method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to forward request: " + err.Error()})
		return
	}

	// Log successful access
	s.db.LogAccess(subjectStr, method, statusCode, c.ClientIP())

	// Return response from node
	c.Data(statusCode, "application/json", responseBody)
}

func (s *Server) getLogs(c *gin.Context) {
	limit := 100 // default
	if limitStr := c.Query("limit"); limitStr != "" {
		if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil {
			limit = 100
		}
	}

	logs, err := s.db.GetAccessLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// localhostOnlyMiddleware restricts access to localhost only
// Works both when running locally and in Docker (when accessed from host)
// When accessed from host via localhost:8080, Docker shows client as gateway IP (172.17.0.1)
// Gin's ClientIP() with trusted proxies will correctly extract the real client IP
//
// SECURITY MODEL:
// - Gin's SetTrustedProxies ensures only requests FROM trusted IPs can set X-Forwarded-For
// - External attackers (e.g., 203.0.113.1) cannot spoof X-Forwarded-For: 127.0.0.1 because:
//  1. Their remote IP (203.0.113.1) is not in the trusted proxy list
//  2. Gin will ignore X-Forwarded-For and use the actual remote IP
//  3. Middleware will reject the request
//
// - Only localhost (127.0.0.1, ::1), Docker network IPs (172.x.x.x), and Tailscale IPs are allowed
func (s *Server) localhostOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Gin's ClientIP() only trusts X-Forwarded-For if remote IP is in trusted proxy list
		// External attackers cannot spoof because their IP won't be trusted
		clientIP := c.ClientIP()

		// Allow localhost IPv4, IPv6
		// Also allow Docker network IPs (172.16.0.0/12 and 192.168.0.0/16) - these come from:
		// - Host accessing via localhost (172.x.x.x gateway)
		// - Frontend container accessing backend (192.168.x.x or 172.x.x.x)
		// Also allow Tailscale IPs (100.64.0.0/10 CGNAT range)
		// Note: Docker networks are isolated by default, so this is safe
		isAllowed := clientIP == "127.0.0.1" ||
			clientIP == "::1" ||
			strings.HasPrefix(clientIP, "172.") ||    // Docker bridge networks (172.16.0.0/12)
			strings.HasPrefix(clientIP, "192.168.") || // Docker custom networks (192.168.0.0/16)
			strings.HasPrefix(clientIP, "100.")       // Tailscale CGNAT (100.64.0.0/10)

		if !isAllowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "management API is only accessible from localhost or Tailscale",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// StatusResponse represents the system status
type StatusResponse struct {
	Proxy ProxyStatus `json:"proxy"`
	Node  NodeStatus  `json:"node"`
}

// ProxyStatus represents the proxy status
type ProxyStatus struct {
	Status string `json:"status"`
	Port   string `json:"port"`
}

// NodeStatus represents the node status
type NodeStatus struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) getStatus(c *gin.Context) {
	// Check node health
	nodeHealth := s.proxy.CheckHealth()

	status := StatusResponse{
		Proxy: ProxyStatus{
			Status: "running",
			Port:   "8080",
		},
		Node: NodeStatus{
			Status:    nodeHealth.Status,
			URL:       nodeHealth.URL,
			LatencyMs: nodeHealth.LatencyMs,
			Error:     nodeHealth.Error,
		},
	}

	c.JSON(http.StatusOK, status)
}

// TestRequestInput represents the input for test request
type TestRequestInput struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

// TestRequestResponse represents the response for test request
type TestRequestResponse struct {
	Success   bool        `json:"success"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	LatencyMs int64       `json:"latency_ms"`
	Blocked   bool        `json:"blocked"`
}

func (s *Server) handleTestRequest(c *gin.Context) {
	var input TestRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use synthetic identity for test requests
	testIdentity := "test:dashboard"

	// Check access via RBAC
	var testRequiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(input.Method, input.Params); claim != "" {
		testRequiredClaims = []rbac.Claim{claim}
	}
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   testIdentity,
		Method:           input.Method,
		Params:           input.Params,
		TargetAddress:    rbac.GetTargetAddress(input.Method, input.Params),
		FunctionSelector: rbac.GetFunctionSelector(input.Method, input.Params),
		RequiredClaims:   testRequiredClaims,
	}
	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), accessReq)
	if err != nil {
		s.db.LogAccess(testIdentity, input.Method, http.StatusInternalServerError, c.ClientIP())
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     "access check failed: " + err.Error(),
			LatencyMs: 0,
			Blocked:   true,
		})
		return
	}
	if !result.Allowed {
		s.db.LogAccess(testIdentity, input.Method, http.StatusForbidden, c.ClientIP())
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     result.Reason,
			LatencyMs: 0,
			Blocked:   true,
		})
		return
	}

	// Build JSON-RPC request
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  input.Method,
		Params:  input.Params,
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)

	// Forward to node and measure latency
	start := time.Now()
	respBody, statusCode, err := s.proxy.Forward(reqBody)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		s.db.LogAccess(testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     err.Error(),
			LatencyMs: latency,
			Blocked:   false,
		})
		return
	}

	// Parse response
	var rpcResp proxy.JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		s.db.LogAccess(testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     "invalid JSON-RPC response",
			LatencyMs: latency,
			Blocked:   false,
		})
		return
	}

	// Log successful access
	s.db.LogAccess(testIdentity, input.Method, statusCode, c.ClientIP())

	if rpcResp.Error != nil {
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     rpcResp.Error.Message,
			LatencyMs: latency,
			Blocked:   false,
		})
		return
	}

	c.JSON(http.StatusOK, TestRequestResponse{
		Success:   true,
		Result:    rpcResp.Result,
		LatencyMs: latency,
		Blocked:   false,
	})
}
