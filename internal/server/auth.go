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
	// Validate verifier ID is configured
	if s.config.VerifierID == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VERIFIER_ID not configured"})
		return
	}

	// Generate session ID first (needed for callback URL)
	sessionID := s.sessionStore.CreateSession(nil) // Create empty session, will update below
	if sessionID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authentication service at capacity, please try again later"})
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
	body, err := io.ReadAll(c.Request.Body)
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
	Error      string `json:"error"`
	Message    string `json:"message"`
	VerifyURL  string `json:"verify_url"`
}

// verifyAndIssueTokens is a helper that verifies JWZ proof and issues JWT tokens
// Returns the response or sends error and returns nil
func (s *Server) verifyAndIssueTokens(c *gin.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, sessionID string) (*AuthResponse, error) {
	var userDID string
	var err error

	// In development mode, support mock tokens for testing
	// Mock token format: mock.{userDID} or mock.jwz.token.{userDID}
	if !s.config.IsProduction() && len(jwzToken) > 5 && jwzToken[:5] == "mock." {
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
		ctx := context.Background()
		userDID, err = s.privadoVerifier.VerifyJWZ(ctx, jwzToken, authRequest, s.config.VerifierID)
		if err != nil {
			// Check if this is a humanity verification failure
			if strings.Contains(err.Error(), "humanity") || strings.Contains(err.Error(), "ProofOfHumanity") {
				c.JSON(http.StatusForbidden, HumanityVerificationError{
					Error:     "humanity_verification_required",
					Message:   "Please complete ProofOfHumanity verification at Billions",
					VerifyURL: "https://app.billions.network",
				})
				return nil, err
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "JWZ verification failed: " + err.Error()})
			return nil, err
		}
	}

	// Ensure user exists in RBAC system and get their KYC status
	// New users default to KYC=false; KYC status is updated through admin API
	kyc := false
	if s.rbacAccessCtrl != nil {
		user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), userDID, kyc)
		if err != nil {
			// Log error but continue - auth can proceed without RBAC user creation
			log.Printf("Warning: failed to ensure RBAC user exists for %s: %v", userDID, err)
		} else if user != nil {
			kyc = user.KYC
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
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	if err := s.db.SaveRefreshToken(tokenHash, userDID, expiresAt); err != nil {
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
		ExpiresIn:    1800, // 30 minutes in seconds
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
			ExpiresIn:    1800,
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
	storedToken, err := s.db.GetRefreshToken(tokenHash)
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
		user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), claims.Subject, false)
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
	if err := s.db.RevokeRefreshToken(tokenHash); err != nil {
		// Log error but continue (non-critical)
		log.Printf("Warning: failed to revoke old refresh token: %v", err)
	}

	// Store new refresh token
	newTokenHash := auth.HashToken(newRefreshToken)
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	if err := s.db.SaveRefreshToken(newTokenHash, claims.Subject, newExpiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save new refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    1800, // 30 minutes in seconds
	})
}

// handleRevoke handles POST /revoke - revokes a refresh token
func (s *Server) handleRevoke(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate token to get subject (optional, but helps with logging)
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		// Even if token is invalid/expired, we can still revoke it (defense in depth)
		// Log but continue
		_ = claims
	}

	// Revoke refresh token
	tokenHash := auth.HashToken(req.RefreshToken)
	if err := s.db.RevokeRefreshToken(tokenHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token revoked successfully"})
}
