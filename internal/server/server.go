package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"privacy-proxy/internal/access"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

type Server struct {
	db              *db.DB
	accessCtrl      *access.Controller
	proxy           *proxy.Proxy
	privadoVerifier PrivadoVerifier
	jwtService      *auth.JWTService
	sessionStore    *auth.SessionStore
	config          *config.Config
}

// DB returns the database instance (for testing)
func (s *Server) DB() *db.DB {
	return s.db
}

// PrivadoVerifier interface for Privado ID operations
type PrivadoVerifier interface {
	CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error)
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

	accessCtrl := access.NewController(database)
	proxySvc := proxy.New(cfg.NodeURL)

	// Initialize session store (10 minute TTL, cleanup every minute)
	sessionStore := auth.NewSessionStore(10*time.Minute, 1*time.Minute)

	return &Server{
		db:              database,
		accessCtrl:      accessCtrl,
		proxy:           proxySvc,
		privadoVerifier: privadoVerifier,
		jwtService:      jwtService,
		sessionStore:    sessionStore,
		config:          cfg,
	}
}

func (s *Server) Run(addr string) error {
	router := gin.Default()

	// Trust Docker network proxies (allows X-Forwarded-For to work correctly)
	// This enables localhost detection when accessing from host to Docker container
	// SECURITY: Only requests FROM these IPs can set X-Forwarded-For headers.
	// External attackers cannot spoof X-Forwarded-For because their IP won't be trusted.
	router.SetTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"})

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
	router.POST("/auth/request", s.handleAuthRequest)      // Step 1: Create proof request
	router.POST("/auth/callback", s.handleAuthCallback)   // Step 2: Wallet callback
	router.POST("/refresh", s.handleRefresh)
	router.POST("/revoke", s.handleRevoke)
	
	// Manual verification endpoint (development/testing only)
	if !s.config.IsProduction() {
		router.POST("/auth/verify", s.handleAuthVerify)
	}

	// JSON-RPC proxy endpoint - protected by JWT
	router.POST("/", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)

	// API endpoints for UI - protected by localhost-only middleware
	api := router.Group("/api")
	api.Use(s.localhostOnlyMiddleware())
	{
		api.GET("/policies", s.listPolicies)
		api.GET("/policies/:id", s.getPolicy)
		api.PUT("/policies/:id", s.updatePolicy)
		api.POST("/policies", s.createPolicy)
		api.DELETE("/policies/:id", s.deletePolicy)
		api.GET("/logs", s.getLogs)
	}

	return router.Run(addr)
}

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

	// Read request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	// Parse method from JSON-RPC request
	method, err := proxy.ParseMethod(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON-RPC request: " + err.Error()})
		return
	}

	// Check access
	if err := s.accessCtrl.CheckAccess(subjectStr, method); err != nil {
		// Log denied access (always log, even if no policy exists)
		s.db.LogAccess(subjectStr, method, http.StatusForbidden, c.ClientIP())
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied: " + err.Error()})
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

func (s *Server) listPolicies(c *gin.Context) {
	policies, err := s.db.ListPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func (s *Server) getPolicy(c *gin.Context) {
	externalID := c.Param("id")
	policy, err := s.db.GetPolicy(externalID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if policy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (s *Server) createPolicy(c *gin.Context) {
	var policy db.AccessPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.db.SetPolicy(&policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

func (s *Server) updatePolicy(c *gin.Context) {
	externalID := c.Param("id")

	// Get existing policy
	existingPolicy, err := s.db.GetPolicy(externalID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if existingPolicy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	// Parse partial update
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Apply updates to existing policy
	if kyc, ok := updates["kyc"].(bool); ok {
		existingPolicy.KYC = kyc
	}
	if allowMethods, ok := updates["allow_methods"].([]interface{}); ok {
		methods := make([]string, 0, len(allowMethods))
		for _, m := range allowMethods {
			if method, ok := m.(string); ok {
				methods = append(methods, method)
			}
		}
		existingPolicy.AllowMethods = methods
	}
	if banned, ok := updates["banned"].(bool); ok {
		existingPolicy.Banned = banned
	}
	if note, ok := updates["note"].(string); ok {
		existingPolicy.Note = note
	}

	// Ensure ExternalID is set
	existingPolicy.ExternalID = externalID

	if err := s.db.SetPolicy(existingPolicy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, existingPolicy)
}

func (s *Server) deletePolicy(c *gin.Context) {
	externalID := c.Param("id")

	if err := s.db.DeletePolicy(externalID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
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
// - Only localhost (127.0.0.1, ::1) and Docker network IPs (172.x.x.x) are allowed
func (s *Server) localhostOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Gin's ClientIP() only trusts X-Forwarded-For if remote IP is in trusted proxy list
		// External attackers cannot spoof because their IP won't be trusted
		clientIP := c.ClientIP()

		// Allow localhost IPv4, IPv6
		// Also allow Docker network IPs (172.16.0.0/12 and 192.168.0.0/16) - these come from:
		// - Host accessing via localhost (172.x.x.x gateway)
		// - Frontend container accessing backend (192.168.x.x or 172.x.x.x)
		// Note: Docker networks are isolated by default, so this is safe
		isLocalhost := clientIP == "127.0.0.1" ||
			clientIP == "::1" ||
			strings.HasPrefix(clientIP, "172.") || // Docker bridge networks (172.16.0.0/12)
			strings.HasPrefix(clientIP, "192.168.") // Docker custom networks (192.168.0.0/16)

		if !isLocalhost {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "management API is only accessible from localhost",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
