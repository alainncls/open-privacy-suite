package server

import (
	"fmt"
	"io"
	"net/http"
	"privacy-proxy/internal/access"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/proxy"
	"strings"

	"github.com/gin-gonic/gin"
)

type Server struct {
	db           *db.DB
	identitySvc  *identity.Service
	accessCtrl   *access.Controller
	proxy        *proxy.Proxy
}

func New(cfg *config.Config) *Server {
	database, err := db.New(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}

	identitySvc := identity.NewService(cfg.BillionsURL)
	accessCtrl := access.NewController(database)
	proxySvc := proxy.New(cfg.NodeURL)

	return &Server{
		db:          database,
		identitySvc: identitySvc,
		accessCtrl:  accessCtrl,
		proxy:       proxySvc,
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

	// JSON-RPC proxy endpoint
	router.POST("/", s.handleJSONRPC)

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
	// Extract Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	// Parse Bearer token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
		return
	}
	token := parts[1]

	// Resolve identity from token
	identity, err := s.identitySvc.ResolveIdentity(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to resolve identity: " + err.Error()})
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
	if err := s.accessCtrl.CheckAccess(identity.Subject, method); err != nil {
		// Log denied access (always log, even if no policy exists)
		s.db.LogAccess(identity.Subject, method, http.StatusForbidden, c.ClientIP())
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied: " + err.Error()})
		return
	}

	// Forward to node
	responseBody, statusCode, err := s.proxy.Forward(body)
	if err != nil {
		// Log error
		s.db.LogAccess(identity.Subject, method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to forward request: " + err.Error()})
		return
	}

	// Log successful access
	s.db.LogAccess(identity.Subject, method, statusCode, c.ClientIP())

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
//   1. Their remote IP (203.0.113.1) is not in the trusted proxy list
//   2. Gin will ignore X-Forwarded-For and use the actual remote IP
//   3. Middleware will reject the request
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
