package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

// getPublicURL extracts the public-facing URL for callbacks.
// Priority: explicit BASE_URL config > dynamic detection from headers
func (s *Server) getPublicURL(c *gin.Context) string {
	// If BASE_URL is explicitly configured (not the default), use it directly.
	// This is the most reliable way to configure external access (ngrok, etc.)
	defaultBaseURL := "http://localhost:8080"
	if s.config.BaseURL != "" && s.config.BaseURL != defaultBaseURL {
		return s.config.BaseURL
	}

	// Dynamic detection for local development
	proto := c.GetHeader("X-Forwarded-Proto")
	if proto == "" {
		if s.config.IsProduction() {
			proto = "https"
		} else {
			proto = "http"
		}
	}

	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}

	if host != "" {
		// Strip any port from the forwarded host
		// For IPv6 literals like [::1]:8080, we want to strip ":8080" but keep [::1]
		// For IPv6 without port like [::1], we don't want to strip at the internal colon
		// Logic: strip port if (not IPv6 literal) OR (IPv6 literal with port, i.e. doesn't end with ])
		hostname := host
		if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
			isIPv6Literal := strings.Contains(host, "[")
			hasPortAfterBracket := !strings.HasSuffix(host, "]")
			if !isIPv6Literal || hasPortAfterBracket {
				hostname = host[:colonIdx]
			}
		}
		port := s.config.Port
		if port == "" {
			port = "8080"
		}
		return fmt.Sprintf("%s://%s:%s", proto, hostname, port)
	}

	return s.config.BaseURL
}

// AuthRequest represents the request body for /auth endpoint
type AuthRequest struct {
	JWZToken string `json:"jwz_token" binding:"required"`
}

// AuthResponse represents the response from /auth endpoint
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// RefreshRequest represents the request body for /refresh endpoint
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RevokeRequest represents the request body for /revoke endpoint
type RevokeRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	AccessToken  string `json:"access_token"` // Optional: if provided, also revokes the access token
}

// AuthRequestResponse represents the response from /auth/request endpoint
type AuthRequestResponse struct {
	SessionID   string                                `json:"session_id"`
	AuthRequest *protocol.AuthorizationRequestMessage `json:"auth_request"`
}

// AuthVerifyRequest represents the request body for /auth/verify endpoint
type AuthVerifyRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	JWZToken  string `json:"jwz_token" binding:"required"`
}

// handleAuthRequest handles POST /auth/request - creates authorization request
// Step 1: Client requests authentication, server creates proof request
func (s *Server) handleAuthRequest(c *gin.Context) {
	// Generate session ID first (needed for callback URL)
	sessionID := s.sessionStore.CreateSession(nil) // Create empty session, will update below
	if sessionID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authentication service at capacity, please try again later"})
		return
	}

	// In development mode with VERIFIER_ID not configured, return a mock session
	// This allows demo recording and testing without Privado infrastructure
	if s.config.VerifierID == "" {
		if s.config.IsProduction() {
			s.sessionStore.DeleteSession(sessionID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "VERIFIER_ID not configured"})
			return
		}
		// Development mode: return mock session for demo/testing
		log.Printf("Warning: VERIFIER_ID not configured - returning mock auth session for development")

		// Create a mock auth request so the frontend can render the QR code
		baseURL := s.getPublicURL(c)
		callbackURL := fmt.Sprintf("%s/auth/callback?session=%s", baseURL, sessionID)
		mockAuthReq := &protocol.AuthorizationRequestMessage{
			ID:   sessionID,
			Typ:  "application/iden3comm-plain-json",
			Type: "https://iden3-communication.io/authorization/1.0/request",
			Body: protocol.AuthorizationRequestMessageBody{
				CallbackURL: callbackURL,
				Reason:      "Authenticate to access Privacy Proxy (demo mode)",
				Scope:       []protocol.ZeroKnowledgeProofRequest{},
			},
			From: "did:privado:verifier:demo-mode",
		}

		c.JSON(http.StatusOK, AuthRequestResponse{
			SessionID:   sessionID,
			AuthRequest: mockAuthReq,
		})

		// Schedule auto-auth for demo mode (if enabled)
		s.scheduleDemoAutoAuth(sessionID)
		return
	}

	// Build callback URL with session ID using dynamic host detection
	// This allows the QR code to work from any hostname (localhost, Tailscale, etc.)
	baseURL := s.getPublicURL(c)
	callbackURL := fmt.Sprintf("%s/auth/callback?session=%s", baseURL, sessionID)

	var authReq *protocol.AuthorizationRequestMessage
	var err error

	// Use ProofOfHumanity auth request when enabled and issuer DID is configured
	if s.config.RequireProofOfHumanity && s.config.BillionsIssuerDID != "" {
		authReq, err = s.privadoVerifier.CreateHumanityAuthRequest(
			s.config.VerifierID,
			callbackURL,
			"Authenticate and verify humanity to access Ethereum node",
			s.config.BillionsIssuerDID,
		)
	} else {
		// Fall back to basic auth (just DID proof)
		authReq, err = s.privadoVerifier.CreateAuthorizationRequest(
			s.config.VerifierID,
			callbackURL,
			"Authenticate to access Ethereum node",
		)
	}
	if err != nil {
		s.sessionStore.DeleteSession(sessionID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create authorization request: " + err.Error()})
		return
	}

	// Update session with the real auth request
	if err := s.sessionStore.UpdateSession(sessionID, authReq); err != nil {
		s.sessionStore.DeleteSession(sessionID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session: " + err.Error()})
		return
	}

	// Return authorization request and session ID
	c.JSON(http.StatusOK, AuthRequestResponse{
		SessionID:   sessionID,
		AuthRequest: authReq,
	})

	// Schedule auto-auth for demo mode (if enabled)
	s.scheduleDemoAutoAuth(sessionID)
}

// scheduleDemoAutoAuth schedules automatic session completion for demo mode.
// Spawns a goroutine that completes the session with a mock DID after the configured delay.
func (s *Server) scheduleDemoAutoAuth(sessionID string) {
	delay := s.config.DemoAutoAuthDelay
	if delay <= 0 || s.config.IsProduction() {
		return
	}

	go func() {
		time.Sleep(delay)

		// Check if session still pending (may have been completed or expired)
		session := s.sessionStore.GetSession(sessionID)
		if session == nil || session.Completed {
			return
		}

		// Generate mock DID and issue tokens
		mockDID := fmt.Sprintf("did:privado:demo_%d", time.Now().UnixNano())
		kyc := false
		if s.rbacAccessCtrl != nil {
			if user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), mockDID, kyc); err == nil && user != nil {
				kyc = user.KYC
			}
		}

		accessToken, err := s.jwtService.IssueAccessToken(mockDID, kyc)
		if err != nil {
			log.Printf("Demo auto-auth: failed to issue access token: %v", err)
			return
		}
		refreshToken, err := s.jwtService.IssueRefreshToken(mockDID)
		if err != nil {
			log.Printf("Demo auto-auth: failed to issue refresh token: %v", err)
			return
		}

		tokenHash := auth.HashToken(refreshToken)
		expiresAt := time.Now().Add(RefreshTokenTTL)
		if err := s.db.SaveRefreshToken(context.Background(), tokenHash, mockDID, expiresAt); err != nil {
			log.Printf("Demo auto-auth: failed to save refresh token: %v", err)
			return
		}

		if err := s.sessionStore.CompleteSession(sessionID, accessToken, refreshToken); err != nil {
			log.Printf("Demo auto-auth: failed to complete session: %v", err)
			return
		}

		log.Printf("Demo auto-auth: session %s completed with DID %s", sessionID, mockDID)
	}()
}

// handleAuthCallback handles POST /auth/callback - wallet callback with proof
// Step 2: Wallet automatically sends proof here after user approves
func (s *Server) handleAuthCallback(c *gin.Context) {
	// Get session ID from query parameter (wallet includes it in callback URL)
	sessionID := c.Query("session")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session parameter required"})
		return
	}

	// Get session
	session := s.sessionStore.GetSession(sessionID)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session not found or expired"})
		return
	}

	// Read JWZ token from request body
	// Wallet sends it as JSON: {"token": "..."} or just the token string
	// Limit body size to 1MB to prevent DoS attacks
	const maxBodySize = 1 << 20 // 1MB
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodySize))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	var jwzToken string
	// Try to parse as JSON first
	var tokenPayload map[string]interface{}
	if err := json.Unmarshal(body, &tokenPayload); err == nil {
		if token, ok := tokenPayload["token"].(string); ok {
			jwzToken = token
		} else if token, ok := tokenPayload["jwz_token"].(string); ok {
			jwzToken = token
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token not found in request body"})
			return
		}
	} else {
		// If not JSON, treat as plain string
		jwzToken = string(body)
	}

	if jwzToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jwz_token required"})
		return
	}

	// Verify proof and issue tokens
	response, err := s.verifyAndIssueTokens(c, jwzToken, session.AuthRequest, sessionID)
	if err != nil {
		return // Error already sent in verifyAndIssueTokens
	}

	c.JSON(http.StatusOK, response)
}

// handleAuthVerify handles POST /auth/verify - manual proof submission (development only)
// Alternative flow for testing: client submits proof manually
func (s *Server) handleAuthVerify(c *gin.Context) {
	var req AuthVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Get session
	session := s.sessionStore.GetSession(req.SessionID)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session not found or expired"})
		return
	}

	// Verify proof and issue tokens
	response, err := s.verifyAndIssueTokens(c, req.JWZToken, session.AuthRequest, req.SessionID)
	if err != nil {
		return // Error already sent in verifyAndIssueTokens
	}

	c.JSON(http.StatusOK, response)
}

// HumanityVerificationError represents a failure to verify ProofOfHumanity
type HumanityVerificationError struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	VerifyURL string `json:"verify_url"`
}

// verifyAndIssueTokens is a helper that verifies JWZ proof and issues JWT tokens
// Returns the response or sends error and returns nil
func (s *Server) verifyAndIssueTokens(c *gin.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, sessionID string) (*AuthResponse, error) {
	var userDID string
	var err error
	var zkClaims *auth.ZKRoleClaims

	// Support mock tokens for testing when explicitly enabled via ALLOW_MOCK_LOGIN=true
	// Mock token format: mock.{userDID} or mock.jwz.token.{userDID}
	if s.config.AllowMockLogin && len(jwzToken) > 5 && jwzToken[:5] == "mock." {
		// Extract DID from mock token
		parts := strings.Split(jwzToken, ".")
		if len(parts) >= 2 {
			// Get the last part which should be the DID
			userDID = parts[len(parts)-1]
			// If DID doesn't have expected prefix, it might be the full mock token
			if !strings.HasPrefix(userDID, "did:") {
				userDID = "did:privado:" + userDID
			}
		}
		if userDID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mock token format"})
			return nil, fmt.Errorf("invalid mock token format")
		}
	} else {
		// Verify JWZ token against the original authorization request
		// Use VerifyJWZWithProofData to get both the DID and any ZK credential data
		verificationResult, verifyErr := s.privadoVerifier.VerifyJWZWithProofData(c.Request.Context(), jwzToken, authRequest, s.config.VerifierID)
		if verifyErr != nil {
			// Check if this is a humanity verification failure
			if strings.Contains(verifyErr.Error(), "humanity") || strings.Contains(verifyErr.Error(), "ProofOfHumanity") {
				c.JSON(http.StatusForbidden, HumanityVerificationError{
					Error:     "humanity_verification_required",
					Message:   "Please complete ProofOfHumanity verification at Billions",
					VerifyURL: "https://app.billions.network",
				})
				return nil, verifyErr
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "JWZ verification failed: " + verifyErr.Error()})
			return nil, verifyErr
		}
		userDID = verificationResult.UserDID

		// Extract ZK role claims from the proof data if available
		if s.zkRoleExtractor != nil && len(verificationResult.ProofData) > 0 {
			// Process each proof's credential data
			for _, proofData := range verificationResult.ProofData {
				claims, extractErr := s.zkRoleExtractor.ExtractRoleClaims(proofData)
				if extractErr != nil {
					log.Printf("Warning: failed to extract ZK role claims: %v", extractErr)
					continue
				}
				if claims != nil && (len(claims.Groups) > 0 || len(claims.Claims) > 0) {
					zkClaims = claims
					break // Use the first proof that has role claims
				}
			}
		}
	}

	// Ensure user exists in RBAC system and get their KYC status
	// New users default to KYC=false; KYC status is updated through admin API
	kyc := false
	var user *rbac.User
	if s.rbacAccessCtrl != nil {
		var err error
		user, err = s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), userDID, kyc)
		if err != nil {
			// Log error but continue - auth can proceed without RBAC user creation
			log.Printf("Warning: failed to ensure RBAC user exists for %s: %v", userDID, err)
		} else if user != nil {
			kyc = user.KYC
		}
	}

	// Process ZK role claims if available and user exists
	// This synchronizes RBAC memberships based on ZK-attested credentials
	if s.zkRoleExtractor != nil && user != nil && zkClaims != nil {
		if err := s.zkRoleExtractor.ProcessZKMemberships(c.Request.Context(), user.ID, zkClaims); err != nil {
			log.Printf("Warning: failed to process ZK memberships for %s: %v", userDID, err)
		}
	}

	// Issue access token (short-lived)
	accessToken, err := s.jwtService.IssueAccessToken(userDID, kyc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access token: " + err.Error()})
		return nil, err
	}

	// Issue refresh token (long-lived)
	refreshToken, err := s.jwtService.IssueRefreshToken(userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue refresh token: " + err.Error()})
		return nil, err
	}

	// Store refresh token in database
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), tokenHash, userDID, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token: " + err.Error()})
		return nil, err
	}

	// Mark session as completed with tokens (keep alive for frontend polling)
	// Session will auto-expire after 2 minutes giving frontend time to poll
	if err := s.sessionStore.CompleteSession(sessionID, accessToken, refreshToken); err != nil {
		// Session may have been deleted or expired - log but continue
		// The wallet still gets the tokens directly from the callback response
		log.Printf("Warning: failed to complete session %s: %v", sessionID, err)
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	}, nil
}

// SessionStatusResponse represents the response for session status polling
type SessionStatusResponse struct {
	Completed bool          `json:"completed"`
	Tokens    *AuthResponse `json:"tokens,omitempty"`
}

// handleAuthSessionStatus handles GET /api/auth/session/:id/status - poll for session completion
// Frontend polls this after displaying QR code to check if wallet has completed auth
func (s *Server) handleAuthSessionStatus(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session ID required"})
		return
	}

	session := s.sessionStore.GetSession(sessionID)
	if session == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}

	if !session.Completed {
		c.JSON(http.StatusOK, SessionStatusResponse{Completed: false})
		return
	}

	// Session is completed - return tokens
	c.JSON(http.StatusOK, SessionStatusResponse{
		Completed: true,
		Tokens: &AuthResponse{
			AccessToken:  session.AccessToken,
			RefreshToken: session.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(AccessTokenTTL.Seconds()),
		},
	})
}

// handleRefresh handles POST /refresh - issues new access token from refresh token
func (s *Server) handleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate refresh token
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		if err == auth.ErrExpiredToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token: " + err.Error()})
		}
		return
	}

	// Check if refresh token is revoked in database
	tokenHash := auth.HashToken(req.RefreshToken)
	storedToken, err := s.db.GetRefreshToken(c.Request.Context(), tokenHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check refresh token: " + err.Error()})
		return
	}

	if storedToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found"})
		return
	}

	if storedToken.Revoked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token revoked"})
		return
	}

	// Check if token expired in database
	expiresAt, err := time.Parse(time.RFC3339, storedToken.ExpiresAt)
	if err == nil && time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	// Get user KYC status from RBAC
	kyc := false
	if s.rbacAccessCtrl != nil {
		user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), claims.Subject, false)
		if err == nil && user != nil {
			kyc = user.KYC
		}
	}

	// Issue new access token
	accessToken, err := s.jwtService.IssueAccessToken(claims.Subject, kyc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access token: " + err.Error()})
		return
	}

	// Optionally rotate refresh token (security best practice)
	// For now, we'll issue a new refresh token and revoke the old one
	newRefreshToken, err := s.jwtService.IssueRefreshToken(claims.Subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue new refresh token: " + err.Error()})
		return
	}

	// Revoke old refresh token
	if err := s.db.RevokeRefreshToken(c.Request.Context(), tokenHash); err != nil {
		// Log error but continue (non-critical)
		log.Printf("Warning: failed to revoke old refresh token: %v", err)
	}

	// Store new refresh token
	newTokenHash := auth.HashToken(newRefreshToken)
	newExpiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), newTokenHash, claims.Subject, newExpiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save new refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	})
}

// IntrospectRequest represents the request body for /introspect endpoint (RFC 7662)
type IntrospectRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"` // Optional: "access_token" or "refresh_token"
}

// IntrospectResponse represents the response from /introspect endpoint (RFC 7662)
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`        // Subject (user DID)
	Exp       int64  `json:"exp,omitempty"`        // Expiration time
	Iat       int64  `json:"iat,omitempty"`        // Issued at time
	TokenType string `json:"token_type,omitempty"` // "access_token" or "refresh_token"
	KYC       bool   `json:"kyc,omitempty"`        // KYC status (only for access tokens)
}

// handleIntrospect handles POST /introspect - token introspection per RFC 7662
// Allows clients to validate tokens and retrieve basic token metadata
func (s *Server) handleIntrospect(c *gin.Context) {
	var req IntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: token is required"})
		return
	}

	// Try to validate as access token first
	accessClaims, accessErr := s.jwtService.ValidateAccessToken(req.Token)
	if accessErr == nil && accessClaims != nil {
		// Check if token is revoked
		tokenID := auth.HashToken(req.Token)
		isRevoked, _ := s.db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
		if isRevoked {
			c.JSON(http.StatusOK, IntrospectResponse{Active: false})
			return
		}

		c.JSON(http.StatusOK, IntrospectResponse{
			Active:    true,
			Sub:       accessClaims.Subject,
			Exp:       accessClaims.ExpiresAt.Unix(),
			Iat:       accessClaims.IssuedAt.Unix(),
			TokenType: "access_token",
			KYC:       accessClaims.KYC,
		})
		return
	}

	// Try to validate as refresh token
	refreshClaims, refreshErr := s.jwtService.ValidateRefreshToken(req.Token)
	if refreshErr == nil && refreshClaims != nil {
		// Check if refresh token is revoked
		tokenHash := auth.HashToken(req.Token)
		storedToken, err := s.db.GetRefreshToken(c.Request.Context(), tokenHash)
		if err != nil || storedToken == nil || storedToken.Revoked {
			c.JSON(http.StatusOK, IntrospectResponse{Active: false})
			return
		}

		c.JSON(http.StatusOK, IntrospectResponse{
			Active:    true,
			Sub:       refreshClaims.Subject,
			Exp:       refreshClaims.ExpiresAt.Unix(),
			Iat:       refreshClaims.IssuedAt.Unix(),
			TokenType: "refresh_token",
		})
		return
	}

	// Token is invalid or expired
	c.JSON(http.StatusOK, IntrospectResponse{Active: false})
}

// handleRevoke handles POST /revoke - revokes refresh and optionally access tokens
func (s *Server) handleRevoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Revoke access token if provided (for immediate invalidation)
	if req.AccessToken != "" {
		accessClaims, err := s.jwtService.ValidateAccessToken(req.AccessToken)
		if err == nil && accessClaims != nil {
			// Token is valid, revoke it by adding to blacklist
			tokenID := auth.HashToken(req.AccessToken)
			if err := s.db.RevokeAccessToken(ctx, tokenID, accessClaims.Subject, accessClaims.ExpiresAt.Time); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke access token: " + err.Error()})
				return
			}
		}
		// If access token is invalid/expired, ignore - it's already unusable
	}

	// Validate refresh token to get subject (optional, but helps with logging)
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		// Even if token is invalid/expired, we can still revoke it (defense in depth)
		_ = claims
	}

	// Revoke refresh token
	tokenHash := auth.HashToken(req.RefreshToken)
	if err := s.db.RevokeRefreshToken(ctx, tokenHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token revoked successfully"})
}
