package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

// OAuth TTL constants
const (
	// OAuthCodeTTL is how long authorization codes are valid (5 minutes)
	OAuthCodeTTL = 5 * time.Minute

	// OAuthSessionTTL is how long OAuth sessions are valid (10 minutes)
	OAuthSessionTTL = 10 * time.Minute

	// OAuthCleanupInterval is how often to clean up expired OAuth sessions
	OAuthCleanupInterval = 1 * time.Minute

	// DefaultMaxOAuthSessions is the default maximum number of concurrent OAuth sessions
	DefaultMaxOAuthSessions = 1000
)

// OAuthSession represents a pending OAuth authorization session
type OAuthSession struct {
	mu sync.Mutex

	// OAuth parameters from the authorize request
	ClientID    string
	RedirectURI string
	State       string

	// Link to the underlying auth session (Privado ID flow)
	AuthSessionID string

	// Authorization code (set after successful auth)
	Code        string
	CodeUsed    bool
	CodeExpires time.Time

	// User info (set after successful auth)
	UserDID string
	KYC     bool

	// Timestamps
	CreatedAt time.Time
	ExpiresAt time.Time
}

// OAuthSessionStore manages OAuth authorization sessions
type OAuthSessionStore struct {
	sessions    sync.Map // map[sessionID]*OAuthSession
	codeIndex   sync.Map // map[code]sessionID - for quick code lookup
	mu          sync.Mutex
	ttl         time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup
	maxSessions int
	count       int64
}

// NewOAuthSessionStore creates a new OAuth session store
func NewOAuthSessionStore(sessionTTL, cleanupInterval time.Duration, maxSessions int) *OAuthSessionStore {
	store := &OAuthSessionStore{
		ttl:         sessionTTL,
		stopCh:      make(chan struct{}),
		maxSessions: maxSessions,
	}

	// Start cleanup goroutine
	store.wg.Add(1)
	go store.cleanup(cleanupInterval)

	return store
}

// CreateSession creates a new OAuth session
// Returns the session ID or empty string if at capacity
func (s *OAuthSessionStore) CreateSession(clientID, redirectURI, state, authSessionID string) string {
	s.mu.Lock()
	if s.maxSessions > 0 && s.count >= int64(s.maxSessions) {
		s.mu.Unlock()
		return ""
	}
	s.count++
	s.mu.Unlock()

	sessionID := generateSecureCode()
	now := time.Now()

	session := &OAuthSession{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		AuthSessionID: authSessionID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.ttl),
	}

	s.sessions.Store(sessionID, session)
	return sessionID
}

// GetSession retrieves an OAuth session by ID
func (s *OAuthSessionStore) GetSession(sessionID string) *OAuthSession {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return nil
	}

	session := value.(*OAuthSession)
	if time.Now().After(session.ExpiresAt) {
		s.deleteSession(sessionID)
		return nil
	}

	return session
}

// GetSessionByCode retrieves an OAuth session by authorization code
func (s *OAuthSessionStore) GetSessionByCode(code string) *OAuthSession {
	value, ok := s.codeIndex.Load(code)
	if !ok {
		return nil
	}

	sessionID := value.(string)
	return s.GetSession(sessionID)
}

// SetCode sets the authorization code for a session
func (s *OAuthSessionStore) SetCode(sessionID, code, userDID string, kyc bool) error {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	session := value.(*OAuthSession)
	session.mu.Lock()
	defer session.mu.Unlock()

	session.Code = code
	session.CodeExpires = time.Now().Add(OAuthCodeTTL)
	session.UserDID = userDID
	session.KYC = kyc

	// Index by code for quick lookup
	s.codeIndex.Store(code, sessionID)

	return nil
}

// MarkCodeUsed marks the authorization code as used (single-use)
func (s *OAuthSessionStore) MarkCodeUsed(code string) bool {
	value, ok := s.codeIndex.Load(code)
	if !ok {
		return false
	}

	sessionID := value.(string)
	sessionValue, ok := s.sessions.Load(sessionID)
	if !ok {
		return false
	}

	session := sessionValue.(*OAuthSession)
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.CodeUsed {
		return false
	}

	session.CodeUsed = true
	return true
}

// DeleteSession removes an OAuth session
func (s *OAuthSessionStore) DeleteSession(sessionID string) {
	s.deleteSession(sessionID)
}

func (s *OAuthSessionStore) deleteSession(sessionID string) {
	value, loaded := s.sessions.LoadAndDelete(sessionID)
	if loaded {
		s.mu.Lock()
		s.count--
		s.mu.Unlock()

		// Clean up code index
		session := value.(*OAuthSession)
		if session.Code != "" {
			s.codeIndex.Delete(session.Code)
		}
	}
}

// cleanup periodically removes expired sessions
func (s *OAuthSessionStore) cleanup(interval time.Duration) {
	defer s.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(key, value any) bool {
				session := value.(*OAuthSession)
				if now.After(session.ExpiresAt) {
					s.deleteSession(key.(string))
				}
				return true
			})
		case <-s.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (s *OAuthSessionStore) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// generateSecureCode generates a cryptographically secure random code
func generateSecureCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fall back to timestamp-based ID (less secure but still unique)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// OAuthAuthorizeRequest represents query parameters for /oauth/authorize
type OAuthAuthorizeRequest struct {
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	State        string `form:"state" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
}

// OAuthTokenRequest represents the request body for /oauth/token
type OAuthTokenRequest struct {
	GrantType   string `json:"grant_type" form:"grant_type" binding:"required"`
	Code        string `json:"code" form:"code" binding:"required"`
	RedirectURI string `json:"redirect_uri" form:"redirect_uri" binding:"required"`
	ClientID    string `json:"client_id" form:"client_id" binding:"required"`
}

// OAuthTokenResponse represents the response from /oauth/token
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// OAuthErrorResponse represents an OAuth error response
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// handleOAuthAuthorize handles GET /oauth/authorize - OAuth authorization endpoint
// This initiates the OAuth flow by creating a pending session and returning the auth page
func (s *Server) handleOAuthAuthorize(c *gin.Context) {
	var req OAuthAuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing required parameters: client_id, redirect_uri, state, response_type",
		})
		return
	}

	// Validate response_type
	if req.ResponseType != "code" {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "unsupported_response_type",
			ErrorDescription: "only response_type=code is supported",
		})
		return
	}

	// Validate redirect_uri
	if !s.isValidRedirectURI(req.RedirectURI) {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "redirect_uri is not allowed",
		})
		return
	}

	// Create the underlying auth session (Privado ID flow)
	authSessionID := s.sessionStore.CreateSession(nil)
	if authSessionID == "" {
		c.JSON(http.StatusServiceUnavailable, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "authentication service at capacity, please try again later",
		})
		return
	}

	// Create OAuth session linked to auth session
	oauthSessionID := s.oauthSessionStore.CreateSession(req.ClientID, req.RedirectURI, req.State, authSessionID)
	if oauthSessionID == "" {
		s.sessionStore.DeleteSession(authSessionID)
		c.JSON(http.StatusServiceUnavailable, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "OAuth service at capacity, please try again later",
		})
		return
	}

	// Generate the authorization request (same as normal auth flow)
	baseURL := s.getPublicURL(c)
	callbackURL := fmt.Sprintf("%s/oauth/callback?session=%s&oauth_session=%s", baseURL, authSessionID, oauthSessionID)

	var authReq *protocol.AuthorizationRequestMessage
	var err error

	// In development mode with VERIFIER_ID not configured, return a mock session
	if s.config.VerifierID == "" {
		if s.config.IsProduction() {
			s.sessionStore.DeleteSession(authSessionID)
			s.oauthSessionStore.DeleteSession(oauthSessionID)
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "VERIFIER_ID not configured",
			})
			return
		}
		// Development mode: create mock auth request via the library
		log.Printf("Warning: VERIFIER_ID not configured - returning mock OAuth auth session for development")
		authReq, err = s.privadoVerifier.CreateAuthorizationRequest(
			devVerifierDID,
			callbackURL,
			"Authenticate for OAuth authorization (demo mode)",
		)
		if err != nil {
			s.sessionStore.DeleteSession(authSessionID)
			s.oauthSessionStore.DeleteSession(oauthSessionID)
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "failed to create mock auth request: " + err.Error(),
			})
			return
		}
	} else {
		// Use ProofOfHumanity auth request when enabled
		if s.config.RequireProofOfHumanity && s.config.BillionsIssuerDID != "" {
			authReq, err = s.privadoVerifier.CreateHumanityAuthRequest(
				s.config.VerifierID,
				callbackURL,
				"Authenticate and verify humanity for OAuth authorization",
				s.config.BillionsIssuerDID,
			)
		} else {
			authReq, err = s.privadoVerifier.CreateAuthorizationRequest(
				s.config.VerifierID,
				callbackURL,
				"Authenticate for OAuth authorization",
			)
		}

		if err != nil {
			s.sessionStore.DeleteSession(authSessionID)
			s.oauthSessionStore.DeleteSession(oauthSessionID)
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "failed to create authorization request",
			})
			return
		}
	}

	// Store the auth request in the session (required for JWZ verification in callback)
	if err := s.sessionStore.UpdateSession(authSessionID, authReq); err != nil {
		s.sessionStore.DeleteSession(authSessionID)
		s.oauthSessionStore.DeleteSession(oauthSessionID)
		c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to store authorization request",
		})
		return
	}

	// Return JSON response with auth request for the client to display QR code
	// The client should poll /oauth/session/:id/status and display the QR code
	c.JSON(http.StatusOK, gin.H{
		"oauth_session_id": oauthSessionID,
		"auth_session_id":  authSessionID,
		"auth_request":     authReq,
	})

	// Schedule auto-auth for demo mode (if enabled)
	s.scheduleOAuthDemoAutoAuth(oauthSessionID, authSessionID)
}

// handleOAuthCallback handles POST /oauth/callback - wallet callback with proof
// This is similar to handleAuthCallback but handles the OAuth redirect
func (s *Server) handleOAuthCallback(c *gin.Context) {
	// Get session IDs from query parameters
	authSessionID := c.Query("session")
	oauthSessionID := c.Query("oauth_session")

	if authSessionID == "" || oauthSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session parameters required"})
		return
	}

	// Get OAuth session
	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OAuth session not found or expired"})
		return
	}

	// SECURITY: Verify the OAuth session is linked to the provided auth session
	// This prevents an attacker from using a valid OAuth session with a different auth session
	if oauthSession.AuthSessionID != authSessionID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session mismatch"})
		return
	}

	// Get auth session
	authSession := s.sessionStore.GetSession(authSessionID)
	if authSession == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "auth session not found or expired"})
		return
	}

	// Read JWZ token from request body (same as normal auth callback)
	body, err := readLimitedBody(c.Request.Body, MaxRequestBodySize)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	jwzToken := extractJWZToken(body)
	if jwzToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jwz_token required"})
		return
	}

	// Verify the proof and get user DID
	var userDID string
	if s.config.AllowMockLogin && len(jwzToken) > 5 && jwzToken[:5] == "mock." {
		// Extract DID from mock token
		parts := strings.Split(jwzToken, ".")
		if len(parts) >= 2 {
			userDID = parts[len(parts)-1]
			if !strings.HasPrefix(userDID, "did:") {
				userDID = "did:privado:" + userDID
			}
		}
		if userDID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mock token format"})
			return
		}
	} else {
		userDID, err = s.privadoVerifier.VerifyJWZ(c.Request.Context(), jwzToken, authSession.AuthRequest, s.config.VerifierID)
		if err != nil {
			if strings.Contains(err.Error(), "humanity") || strings.Contains(err.Error(), "ProofOfHumanity") {
				c.JSON(http.StatusForbidden, HumanityVerificationError{
					Error:     "humanity_verification_required",
					Message:   "Please complete ProofOfHumanity verification at Billions",
					VerifyURL: "https://app.billions.network",
				})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "JWZ verification failed: " + err.Error()})
			return
		}
	}

	// Get user KYC status from RBAC
	kyc := false
	if s.rbacAccessCtrl != nil {
		user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), userDID, kyc)
		if err == nil && user != nil {
			kyc = user.KYC
		}
	}

	// Generate authorization code
	code := generateSecureCode()

	// Store the code in the OAuth session
	if err := s.oauthSessionStore.SetCode(oauthSessionID, code, userDID, kyc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate authorization code"})
		return
	}

	// Mark auth session as completed (for status polling)
	// We don't store the actual tokens here - those are issued at the token endpoint
	if err := s.sessionStore.CompleteSession(authSessionID, "", ""); err != nil {
		log.Printf("Warning: failed to complete auth session %s: %v", authSessionID, err)
	}

	// Build redirect URL with code and state
	redirectURL, err := url.Parse(oauthSession.RedirectURI)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid redirect URI"})
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", oauthSession.State)
	redirectURL.RawQuery = q.Encode()

	// Return the redirect URL (wallet will follow it)
	// Also return success for the wallet callback
	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"redirect_url": redirectURL.String(),
	})
}

// handleOAuthToken handles POST /oauth/token - Token endpoint
// Exchanges authorization code for JWT access token
func (s *Server) handleOAuthToken(c *gin.Context) {
	var req OAuthTokenRequest

	// Support both JSON and form-encoded requests (OAuth spec allows both)
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, OAuthErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request body",
			})
			return
		}
	} else {
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, OAuthErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request body",
			})
			return
		}
	}

	// Validate grant_type
	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "only grant_type=authorization_code is supported",
		})
		return
	}

	// Look up session by code
	session := s.oauthSessionStore.GetSessionByCode(req.Code)
	if session == nil {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "authorization code not found or expired",
		})
		return
	}

	// Validate client_id matches
	if session.ClientID != req.ClientID {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "client_id does not match",
		})
		return
	}

	// Validate redirect_uri matches
	if session.RedirectURI != req.RedirectURI {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "redirect_uri does not match",
		})
		return
	}

	// Check if code has expired
	if time.Now().After(session.CodeExpires) {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "authorization code has expired",
		})
		return
	}

	// Mark code as used (single-use)
	if !s.oauthSessionStore.MarkCodeUsed(req.Code) {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "authorization code has already been used",
		})
		return
	}

	// Issue access token (same JWT format as regular auth)
	accessToken, err := s.jwtService.IssueAccessToken(session.UserDID, session.KYC)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to issue access token",
		})
		return
	}

	// Return token response
	c.JSON(http.StatusOK, OAuthTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(AccessTokenTTL.Seconds()),
	})
}

// OAuthSessionStatusResponse represents the response for OAuth session status polling
type OAuthSessionStatusResponse struct {
	Completed   bool   `json:"completed"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// handleOAuthSessionStatus handles GET /oauth/session/:id/status - poll for OAuth session completion
// Frontend polls this to check if the user has completed Privado auth
func (s *Server) handleOAuthSessionStatus(c *gin.Context) {
	oauthSessionID := c.Param("id")
	if oauthSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session ID required"})
		return
	}

	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}

	// Check if code has been generated (means auth completed)
	if oauthSession.Code == "" {
		c.JSON(http.StatusOK, OAuthSessionStatusResponse{Completed: false})
		return
	}

	// Build redirect URL with code and state
	redirectURL, err := url.Parse(oauthSession.RedirectURI)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid redirect URI"})
		return
	}

	q := redirectURL.Query()
	q.Set("code", oauthSession.Code)
	q.Set("state", oauthSession.State)
	redirectURL.RawQuery = q.Encode()

	c.JSON(http.StatusOK, OAuthSessionStatusResponse{
		Completed:   true,
		RedirectURL: redirectURL.String(),
	})
}

// isValidRedirectURI validates that the redirect URI is allowed.
// Compares the full origin (scheme + host + port) against an allowlist:
// - localhost (any port) — development only
// - The configured BASE_URL origin
// - Configured CORS allowed origins (explicit list, not "*")
func (s *Server) isValidRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// Must be http or https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Extract origin (scheme + host + port) from the redirect URI
	uriOrigin := parsed.Scheme + "://" + parsed.Host // Host includes port if present

	host := parsed.Hostname()

	// Allow localhost in development only
	if !s.config.IsProduction() {
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return true
		}
	}

	// Allow the configured BASE_URL origin (full origin match)
	if s.config.BaseURL != "" {
		baseURL, err := url.Parse(s.config.BaseURL)
		if err == nil {
			baseOrigin := baseURL.Scheme + "://" + baseURL.Host
			if uriOrigin == baseOrigin {
				return true
			}
		}
	}

	// Allow configured CORS origins (explicit list only, "*" does NOT allow arbitrary redirect URIs)
	if s.config.CORSAllowedOrigins != "" && s.config.CORSAllowedOrigins != "*" {
		for _, origin := range strings.Split(s.config.CORSAllowedOrigins, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" && origin == uriOrigin {
				return true
			}
		}
	}

	return false
}

// scheduleOAuthDemoAutoAuth schedules automatic OAuth session completion for demo mode
func (s *Server) scheduleOAuthDemoAutoAuth(oauthSessionID, authSessionID string) {
	delay := s.config.DemoAutoAuthDelay
	if delay <= 0 || s.config.IsProduction() {
		return
	}

	go func() {
		time.Sleep(delay)

		// Check if OAuth session still pending
		oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
		if oauthSession == nil || oauthSession.Code != "" {
			return
		}

		// Generate mock DID and complete the OAuth flow
		mockDID := fmt.Sprintf("did:privado:demo_%d", time.Now().UnixNano())
		kyc := false
		if s.rbacAccessCtrl != nil {
			if user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), mockDID, kyc); err == nil && user != nil {
				kyc = user.KYC
			}
		}

		// Generate authorization code
		code := generateSecureCode()
		if err := s.oauthSessionStore.SetCode(oauthSessionID, code, mockDID, kyc); err != nil {
			log.Printf("Demo OAuth auto-auth: failed to set code: %v", err)
			return
		}

		// Mark auth session as completed
		if err := s.sessionStore.CompleteSession(authSessionID, "", ""); err != nil {
			log.Printf("Demo OAuth auto-auth: failed to complete auth session: %v", err)
		}

		log.Printf("Demo OAuth auto-auth: session %s completed with DID %s", oauthSessionID, mockDID)
	}()
}

// Helper functions

// readLimitedBody reads a request body with a size limit
func readLimitedBody(body interface{ Read([]byte) (int, error) }, maxSize int64) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	total := int64(0)
	for {
		if total >= maxSize {
			return nil, fmt.Errorf("body too large")
		}
		chunk := make([]byte, 1024)
		n, err := body.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

// extractJWZToken extracts the JWZ token from the request body
// Supports both JSON format and plain string
func extractJWZToken(body []byte) string {
	// Try JSON parsing
	var tokenPayload map[string]interface{}
	if err := json.Unmarshal(body, &tokenPayload); err == nil {
		if token, ok := tokenPayload["token"].(string); ok {
			return token
		}
		if token, ok := tokenPayload["jwz_token"].(string); ok {
			return token
		}
	}
	// Fall back to plain string
	return strings.TrimSpace(string(body))
}
