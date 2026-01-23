package server

import (
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

// TTL constants for various components
const (
	// JWT token TTLs
	AccessTokenTTL  = 30 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour

	// Cache and store TTLs
	RBACCacheTTL             = 5 * time.Minute
	SessionTTL               = 10 * time.Minute
	SessionCleanupInterval   = 1 * time.Minute
	ChallengeTTL             = 5 * time.Minute
	ChallengeCleanupInterval = 1 * time.Minute

	// Rate limiter cleanup interval
	RateLimiterCleanupInterval = 10 * time.Second

	// ENS resolution timeout
	ENSResolutionTimeout = 30 * time.Second
)

type Server struct {
	db               *db.DB
	rbacAccessCtrl   *rbac.AccessController
	proxy            *proxy.Proxy
	privadoVerifier  PrivadoVerifier
	jwtService       *auth.JWTService
	sessionStore     SessionManager
	challengeStore   *ChallengeStore
	rateLimiter      RateLimiterInterface
	authRateLimiter  *AuthRateLimiter
	config           *config.Config
	ensResolver      *ens.Resolver
	jsonrpcProcessor *JSONRPCProcessor
	zkRoleExtractor  *auth.ZKRoleExtractor
}

// DB returns the database instance (for testing)
func (s *Server) DB() *db.DB {
	return s.db
}

// Stop gracefully stops all background goroutines.
// Should be called before server shutdown.
func (s *Server) Stop() {
	if s.sessionStore != nil {
		s.sessionStore.Stop()
	}
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	if s.authRateLimiter != nil {
		s.authRateLimiter.Stop()
	}
	if s.challengeStore != nil {
		s.challengeStore.Stop()
	}
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.Stop()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// PrivadoVerifier interface for Privado ID operations
type PrivadoVerifier interface {
	CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error)
	CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string) (*protocol.AuthorizationRequestMessage, error)
	VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error)
	VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error)
}

func New(cfg *config.Config) (*Server, error) {
	return NewWithVerifier(cfg, nil)
}

// NewWithVerifier creates a new server with an optional PrivadoVerifier
// If verifier is nil, creates a real PrivadoVerifier from config
// This allows injecting a mock verifier for testing
func NewWithVerifier(cfg *config.Config, verifier PrivadoVerifier) (*Server, error) {
	database, err := db.New(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Initialize Privado ID verifier
	var privadoVerifier PrivadoVerifier
	if verifier != nil {
		privadoVerifier = verifier
	} else {
		privadoVerifier, err = auth.NewPrivadoVerifier(cfg.PrivadoRPCURL, cfg.IPFSGateway)
		if err != nil {
			database.Close()
			return nil, fmt.Errorf("failed to create Privado verifier: %w", err)
		}
	}

	// Initialize JWT service
	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		cfg.JWTRefreshSecret,
		AccessTokenTTL,
		RefreshTokenTTL,
	)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("failed to create JWT service: %w", err)
	}

	proxySvc := proxy.New(cfg.NodeURL)

	// Initialize RBAC access controller
	// Note: Unregistered address handling is now controlled by default_claims in GroupAccess
	rbacAccessCtrl := rbac.NewAccessController(database, RBACCacheTTL)

	// Initialize session store
	sessionStore := auth.NewSessionStore(SessionTTL, SessionCleanupInterval)

	// Initialize challenge store for ETH address linking
	challengeStore := NewChallengeStore(ChallengeTTL, ChallengeCleanupInterval)

	// Initialize rate limiter
	rateLimiter := NewRateLimiter(RateLimiterCleanupInterval)

	// Initialize auth rate limiter for protecting auth endpoints from brute force
	// Use relaxed limits in development/testing to avoid issues during E2E tests
	var authRateLimiterCfg AuthRateLimiterConfig
	if cfg.IsProduction() {
		authRateLimiterCfg = DefaultAuthRateLimiterConfig()
	} else {
		authRateLimiterCfg = DevAuthRateLimiterConfig()
	}
	authRateLimiter := NewAuthRateLimiter(authRateLimiterCfg)

	// Initialize ENS resolver (optional - may fail if no mainnet RPC available)
	var ensResolver *ens.Resolver
	if cfg.ENSResolverURL != "" {
		ensResolver, err = ens.NewResolver(cfg.ENSResolverURL)
		if err != nil {
			// Log warning but don't fail - ENS resolution is optional
			fmt.Printf("Warning: failed to create ENS resolver: %v\n", err)
		}
	}

	// Initialize ZK role extractor for extracting role claims from Privado proofs
	zkRoleExtractor := auth.NewZKRoleExtractor(database)

	s := &Server{
		db:              database,
		rbacAccessCtrl:  rbacAccessCtrl,
		proxy:           proxySvc,
		privadoVerifier: privadoVerifier,
		jwtService:      jwtService,
		sessionStore:    sessionStore,
		challengeStore:  challengeStore,
		rateLimiter:     rateLimiter,
		authRateLimiter: authRateLimiter,
		config:          cfg,
		ensResolver:     ensResolver,
		zkRoleExtractor: zkRoleExtractor,
	}

	// Initialize JSON-RPC processor with dependencies
	s.jsonrpcProcessor = NewJSONRPCProcessor(rbacAccessCtrl, rateLimiter, proxySvc, database)

	return s, nil
}

func (s *Server) Run(addr string) error {
	router := s.setupRouter()
	return router.Run(addr)
}

// RunWithServer runs the server with a custom http.Server for graceful shutdown support.
func (s *Server) RunWithServer(httpServer *http.Server) error {
	router := s.setupRouter()
	httpServer.Handler = router
	return httpServer.ListenAndServe()
}

func (s *Server) setupRouter() *gin.Engine {
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
	router.Use(s.corsMiddleware())

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
	// Rate limited to prevent brute force attacks
	authRL := s.authRateLimiter.Middleware()

	// Register at both root level (for direct access) and under /api (for frontend proxy)
	router.POST("/auth/request", authRL, s.handleAuthRequest)
	router.POST("/auth/callback", authRL, s.handleAuthCallback)
	router.POST("/refresh", authRL, s.handleRefresh)
	router.POST("/revoke", authRL, s.handleRevoke)
	router.POST("/introspect", authRL, s.handleIntrospect)

	// Versioned API auth endpoints (v1) - primary path
	router.POST("/api/v1/auth/request", authRL, s.handleAuthRequest)
	router.POST("/api/v1/auth/callback", authRL, s.handleAuthCallback)
	router.GET("/api/v1/auth/session/:id/status", s.handleAuthSessionStatus)
	router.POST("/api/v1/refresh", authRL, s.handleRefresh)
	router.POST("/api/v1/revoke", authRL, s.handleRevoke)
	router.POST("/api/v1/introspect", authRL, s.handleIntrospect)

	// Legacy API auth endpoints (unversioned) - deprecated, for backwards compatibility
	deprecation := s.deprecationMiddleware("/api", "/api/v1")
	router.POST("/api/auth/request", authRL, deprecation, s.handleAuthRequest)
	router.POST("/api/auth/callback", authRL, deprecation, s.handleAuthCallback)
	router.GET("/api/auth/session/:id/status", deprecation, s.handleAuthSessionStatus)
	router.POST("/api/refresh", authRL, deprecation, s.handleRefresh)
	router.POST("/api/revoke", authRL, deprecation, s.handleRevoke)
	router.POST("/api/introspect", authRL, deprecation, s.handleIntrospect)

	// Manual verification endpoint (development/testing only)
	if !s.config.IsProduction() {
		router.POST("/auth/verify", authRL, s.handleAuthVerify)
		router.POST("/api/v1/auth/verify", authRL, s.handleAuthVerify)
		router.POST("/api/auth/verify", authRL, deprecation, s.handleAuthVerify)
	}

	// ETH address linking endpoints - available at multiple paths for flexibility:
	// - /api/v1/eth/* - versioned API (primary)
	// - /api/eth/* - legacy unversioned (deprecated)
	// - /eth/* - for direct API access (mobile apps, CLI tools)
	// All require JWT authentication.
	ethEndpoints := func(group *gin.RouterGroup) {
		group.POST("/link/challenge", s.handleEthLinkChallenge)
		group.POST("/link/verify", s.handleEthLinkVerify)
		group.GET("/addresses", s.handleGetEthAddresses)
		group.DELETE("/addresses/:address", s.handleDeleteEthAddress)
		group.POST("/addresses/:address/refresh-ens", s.handleRefreshENS)
	}

	// Versioned API eth endpoints (v1) - primary
	apiV1Eth := router.Group("/api/v1/eth")
	apiV1Eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	ethEndpoints(apiV1Eth)

	// Legacy API eth endpoints (unversioned) - deprecated
	apiEth := router.Group("/api/eth")
	apiEth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	apiEth.Use(deprecation)
	ethEndpoints(apiEth)

	// Direct eth endpoints (no /api prefix)
	eth := router.Group("/eth")
	eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	ethEndpoints(eth)

	// JSON-RPC proxy endpoint - protected by JWT
	// Support both "/" (direct access) and "/rpc" (frontend proxy)
	router.POST("/", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)
	router.POST("/rpc", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)

	// API endpoints for UI - protected by localhost-only middleware
	// Register versioned API (v1) - primary path
	apiV1 := router.Group("/api/v1")
	apiV1.Use(s.localhostOnlyMiddleware())
	{
		apiV1.GET("/logs", s.getLogs)
		apiV1.GET("/status", s.getStatus)
		apiV1.POST("/test-request", s.handleTestRequest)

		// RBAC endpoints
		s.registerRBACRoutes(apiV1)
	}

	// Legacy API (unversioned) - deprecated, for backwards compatibility
	// Adds X-Deprecated header to responses
	api := router.Group("/api")
	api.Use(s.localhostOnlyMiddleware())
	api.Use(s.deprecationMiddleware("/api", "/api/v1"))
	{
		api.GET("/logs", s.getLogs)
		api.GET("/status", s.getStatus)
		api.POST("/test-request", s.handleTestRequest)

		// RBAC endpoints
		s.registerRBACRoutes(api)
	}

	return router
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

	// Parse and validate the request body
	method, params, parseErr := ParseAndValidateBody(body)
	if parseErr != nil {
		c.JSON(parseErr.StatusCode, gin.H{"error": parseErr.Message})
		return
	}

	// Process the request through the business logic layer
	result := s.jsonrpcProcessor.Process(c.Request.Context(), &ProcessRequest{
		UserID:   subjectStr,
		Method:   method,
		Params:   params,
		Body:     body,
		ClientIP: c.ClientIP(),
	})

	// Handle errors from processing
	if result.Error != nil {
		c.JSON(result.Error.StatusCode, gin.H{"error": result.Error.Message})
		return
	}

	// Return response from node
	c.Data(result.StatusCode, "application/json", result.ResponseBody)
}

func (s *Server) getLogs(c *gin.Context) {
	limit := 100 // default
	if limitStr := c.Query("limit"); limitStr != "" {
		if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil {
			limit = 100
		}
	}

	logs, err := s.db.GetAccessLogs(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// corsMiddleware returns a CORS middleware configured from server settings.
// In development (or with CORSAllowedOrigins="*"), allows all origins.
// In production, only allows configured origins.
func (s *Server) corsMiddleware() gin.HandlerFunc {
	allowedOrigins := s.config.CORSAllowedOrigins

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Determine if this origin should be allowed
		var allowOrigin string
		if allowedOrigins == "*" {
			allowOrigin = "*"
		} else if allowedOrigins != "" {
			// Check if origin is in the allowed list
			for _, allowed := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(allowed) == origin {
					allowOrigin = origin
					break
				}
			}
		}

		if allowOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// deprecationMiddleware adds deprecation headers to responses.
// It signals to clients that they should migrate to the versioned API.
func (s *Server) deprecationMiddleware(oldPath, newPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add deprecation headers per RFC 8594
		c.Header("Deprecation", "true")
		c.Header("Sunset", "2027-01-01T00:00:00Z") // Give clients a year to migrate
		c.Header("Link", fmt.Sprintf("<%s%s>; rel=\"successor-version\"", newPath, strings.TrimPrefix(c.Request.URL.Path, oldPath)))
		c.Next()
	}
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
			strings.HasPrefix(clientIP, "172.") || // Docker bridge networks (172.16.0.0/12)
			strings.HasPrefix(clientIP, "192.168.") || // Docker custom networks (192.168.0.0/16)
			strings.HasPrefix(clientIP, "100.") // Tailscale CGNAT (100.64.0.0/10)

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
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusInternalServerError, c.ClientIP())
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     "access check failed: " + err.Error(),
			LatencyMs: 0,
			Blocked:   true,
		})
		return
	}
	if !result.Allowed {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusForbidden, c.ClientIP())
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
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
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
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusOK, TestRequestResponse{
			Success:   false,
			Error:     "invalid JSON-RPC response",
			LatencyMs: latency,
			Blocked:   false,
		})
		return
	}

	// Log successful access
	s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, statusCode, c.ClientIP())

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
