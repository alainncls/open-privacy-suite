package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestServerForOAuth creates a test server with OAuth support
func setupTestServerForOAuth(t *testing.T) *Server {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development (no external PostgreSQL needed)
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Reset database (drops all tables and runs migrations)
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	// Create JWT service
	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	// Create mock Privado verifier
	mockVerifier := &mockPrivadoVerifier{
		verifyFunc: func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
			// Mock: accept any JWZ token and return a test DID
			if jwzToken == "" {
				return "", fmt.Errorf("empty JWZ token")
			}
			return "did:privado:test123", nil
		},
	}

	// Create test config
	cfg := &config.Config{
		VerifierID:         "did:privado:verifier:test",
		BaseURL:            "http://localhost:8080",
		Environment:        "development",
		CORSAllowedOrigins: "",
	}

	srv := &Server{
		db:                database,
		privadoVerifier:   mockVerifier,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbac.NewAccessController(database, 5*time.Minute),
		proxy:             nil, // Not needed for OAuth tests
		sessionStore:      auth.NewSessionStore(10*time.Minute, 1*time.Minute),
		oauthSessionStore: NewOAuthSessionStore(OAuthSessionTTL, OAuthCleanupInterval, DefaultMaxOAuthSessions),
		config:            cfg,
	}

	return srv
}

// TestOAuth_AuthorizeEndpoint tests the OAuth authorize endpoint
func TestOAuth_AuthorizeEndpoint(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		queryParams    map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "valid request with all required parameters",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing client_id",
			queryParams: map[string]string{
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "missing redirect_uri",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"response_type": "code",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "missing response_type",
			queryParams: map[string]string{
				"client_id":    "explorer-app",
				"redirect_uri": "http://localhost:3000/callback",
				"state":        "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "missing state",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "invalid response_type - token not supported",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "token", // Should be "code" for authorization code flow
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "unsupported_response_type",
		},
		{
			name: "invalid response_type - implicit flow not supported",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "id_token",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "unsupported_response_type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

			// Build query string
			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}

			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errResp OAuthErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedError, errResp.Error)
			}

			if tt.expectedStatus == http.StatusOK {
				var resp map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp["oauth_session_id"])
				assert.NotEmpty(t, resp["auth_session_id"])
				assert.NotNil(t, resp["auth_request"])
			}
		})
	}
}

// TestOAuth_TokenEndpoint tests the OAuth token exchange endpoint
func TestOAuth_TokenEndpoint(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupSession   func() string // returns the authorization code
		requestBody    func(code string) OAuthTokenRequest
		expectedStatus int
		expectedError  string
		checkResponse  func(t *testing.T, resp OAuthTokenResponse)
	}{
		{
			name: "valid code exchange returns JWT",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-1")
				require.NotEmpty(t, oauthSessionID)
				code := generateSecureCode()
				err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				require.NoError(t, err)
				return code
			},
			requestBody: func(code string) OAuthTokenRequest {
				return OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp OAuthTokenResponse) {
				assert.NotEmpty(t, resp.AccessToken)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.Greater(t, resp.ExpiresIn, 0)

				// Validate the access token
				claims, err := srv.jwtService.ValidateAccessToken(resp.AccessToken)
				require.NoError(t, err)
				assert.Equal(t, "did:privado:test123", claims.Subject)
				assert.True(t, claims.KYC)
			},
		},
		{
			name: "invalid code returns error",
			setupSession: func() string {
				return "invalid-code"
			},
			requestBody: func(code string) OAuthTokenRequest {
				return OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_grant",
		},
		{
			name: "invalid grant_type returns error",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-2")
				code := generateSecureCode()
				srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				return code
			},
			requestBody: func(code string) OAuthTokenRequest {
				return OAuthTokenRequest{
					GrantType:   "password",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "unsupported_grant_type",
		},
		{
			name: "mismatched redirect_uri returns error",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-3")
				code := generateSecureCode()
				srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				return code
			},
			requestBody: func(code string) OAuthTokenRequest {
				return OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://malicious-site.com/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_grant",
		},
		{
			name: "mismatched client_id returns error",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-4")
				code := generateSecureCode()
				srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				return code
			},
			requestBody: func(code string) OAuthTokenRequest {
				return OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "wrong-client",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.POST("/oauth/token", srv.handleOAuthToken)

			code := tt.setupSession()
			tokenReq := tt.requestBody(code)
			reqBody, _ := json.Marshal(tokenReq)

			req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errResp OAuthErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedError, errResp.Error)
			}

			if tt.checkResponse != nil && tt.expectedStatus == http.StatusOK {
				var resp OAuthTokenResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				tt.checkResponse(t, resp)
			}
		})
	}
}

// TestOAuth_TokenEndpoint_FormEncoded tests the token endpoint with form-encoded requests
func TestOAuth_TokenEndpoint_FormEncoded(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a valid session
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-form")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	// Build form-encoded body
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("redirect_uri", "http://localhost:3000/callback")
	formData.Set("client_id", "explorer-app")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp OAuthTokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

// TestOAuth_CodeReplayProtection tests that authorization codes can only be used once
func TestOAuth_CodeReplayProtection(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a valid session with a code
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-replay")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	// First use should succeed
	req1 := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	var resp OAuthTokenResponse
	err = json.Unmarshal(w1.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// Second use should fail (replay protection)
	req2 := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusBadRequest, w2.Code)

	var errResp OAuthErrorResponse
	err = json.Unmarshal(w2.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "already been used")
}

// TestOAuth_RedirectURIValidation tests redirect URI validation rules
func TestOAuth_RedirectURIValidation(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Update config with allowed redirect URIs
	srv.config.BaseURL = "https://explorer.example.com"

	tests := []struct {
		name           string
		redirectURI    string
		expectedStatus int
		description    string
	}{
		{
			name:           "localhost http allowed",
			redirectURI:    "http://localhost:3000/callback",
			expectedStatus: http.StatusOK,
			description:    "localhost URLs should be allowed for development",
		},
		{
			name:           "localhost https allowed",
			redirectURI:    "https://localhost:3000/callback",
			expectedStatus: http.StatusOK,
			description:    "localhost with HTTPS should be allowed",
		},
		{
			name:           "localhost with different port allowed",
			redirectURI:    "http://localhost:8080/oauth/callback",
			expectedStatus: http.StatusOK,
			description:    "localhost with any port should be allowed",
		},
		{
			name:           "127.0.0.1 allowed",
			redirectURI:    "http://127.0.0.1:3000/callback",
			expectedStatus: http.StatusOK,
			description:    "127.0.0.1 should be allowed for development",
		},
		{
			name:           "configured base URL allowed",
			redirectURI:    "https://explorer.example.com/callback",
			expectedStatus: http.StatusOK,
			description:    "configured BASE_URL should be allowed",
		},
		{
			name:           "arbitrary external URL rejected",
			redirectURI:    "https://evil.com/steal-token",
			expectedStatus: http.StatusBadRequest,
			description:    "arbitrary external URLs should be rejected",
		},
		{
			name:           "external URL with similar domain rejected",
			redirectURI:    "https://explorer.example.com.evil.com/callback",
			expectedStatus: http.StatusBadRequest,
			description:    "domains that look similar but aren't should be rejected",
		},
		{
			name:           "http external URL rejected",
			redirectURI:    "http://external-site.com/callback",
			expectedStatus: http.StatusBadRequest,
			description:    "non-localhost HTTP URLs should be rejected",
		},
		{
			name:           "javascript URL rejected",
			redirectURI:    "javascript:alert('xss')",
			expectedStatus: http.StatusBadRequest,
			description:    "javascript: URLs should be rejected",
		},
		{
			name:           "data URL rejected",
			redirectURI:    "data:text/html,<script>alert('xss')</script>",
			expectedStatus: http.StatusBadRequest,
			description:    "data: URLs should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

			q := url.Values{}
			q.Set("client_id", "explorer-app")
			q.Set("redirect_uri", tt.redirectURI)
			q.Set("response_type", "code")
			q.Set("state", "test-state")

			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

// TestOAuth_RedirectURIValidation_CORSOrigins tests that CORS allowed origins work as redirect URIs
func TestOAuth_RedirectURIValidation_CORSOrigins(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Set up CORS allowed origins
	srv.config.CORSAllowedOrigins = "https://app1.example.com,https://app2.example.com"
	srv.config.BaseURL = "https://privacy-proxy.example.com"

	tests := []struct {
		name           string
		redirectURI    string
		expectedStatus int
	}{
		{
			name:           "CORS origin app1 allowed",
			redirectURI:    "https://app1.example.com/callback",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "CORS origin app2 allowed",
			redirectURI:    "https://app2.example.com/oauth/callback",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "non-CORS origin rejected",
			redirectURI:    "https://app3.example.com/callback",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

			q := url.Values{}
			q.Set("client_id", "explorer-app")
			q.Set("redirect_uri", tt.redirectURI)
			q.Set("response_type", "code")
			q.Set("state", "test-state")

			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// TestOAuth_RedirectURIValidation_WildcardCORS tests that wildcard CORS allows all redirect URIs
func TestOAuth_RedirectURIValidation_WildcardCORS(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Set up wildcard CORS
	srv.config.CORSAllowedOrigins = "*"

	router := gin.New()
	router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

	// With wildcard CORS, any HTTPS URL should be allowed
	q := url.Values{}
	q.Set("client_id", "explorer-app")
	q.Set("redirect_uri", "https://any-site.com/callback")
	q.Set("response_type", "code")
	q.Set("state", "test-state")

	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestOAuth_SessionStatus tests the session status polling endpoint
func TestOAuth_SessionStatus(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/session/:id/status", srv.handleOAuthSessionStatus)

	t.Run("incomplete session", func(t *testing.T) {
		// Create a session without a code
		oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-incomplete")
		require.NotEmpty(t, oauthSessionID)

		req := httptest.NewRequest("GET", "/oauth/session/"+oauthSessionID+"/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp OAuthSessionStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Completed)
		assert.Empty(t, resp.RedirectURL)
	})

	t.Run("completed session", func(t *testing.T) {
		// Create a session with a code
		oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-complete")
		require.NotEmpty(t, oauthSessionID)
		code := generateSecureCode()
		err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/oauth/session/"+oauthSessionID+"/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp OAuthSessionStatusResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Completed)
		assert.Contains(t, resp.RedirectURL, code)
		assert.Contains(t, resp.RedirectURL, "state=test-state")
	})

	t.Run("non-existent session", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/oauth/session/non-existent-id/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestOAuth_SessionExpiry tests that OAuth sessions/codes expire properly
func TestOAuth_SessionExpiry(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a session store with very short TTL
	shortTTLStore := NewOAuthSessionStore(50*time.Millisecond, 1*time.Hour, 100)
	defer shortTTLStore.Stop()
	srv.oauthSessionStore = shortTTLStore

	// Create a session
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-expiry")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(100 * time.Millisecond)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)
}

// TestOAuth_CodeExpiry tests that authorization codes expire after OAuthCodeTTL
func TestOAuth_CodeExpiry(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a session with a code
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-code-expiry")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	// Manually expire the code by modifying the session
	session := srv.oauthSessionStore.GetSession(oauthSessionID)
	require.NotNil(t, session)
	session.CodeExpires = time.Now().Add(-1 * time.Second) // Set to past

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "expired")
}

// TestOAuth_StateParameterPreserved tests that the state parameter is preserved through the flow
func TestOAuth_StateParameterPreserved(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/session/:id/status", srv.handleOAuthSessionStatus)

	// Test various state values
	states := []string{
		"simple-state",
		"state-with-special-chars-!@#$%",
		"base64encodedstate==",
		"very-long-state-value-" + strings.Repeat("x", 100),
	}

	for _, state := range states {
		t.Run("state="+state[:minInt(20, len(state))], func(t *testing.T) {
			// Create a session with the state
			oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", state, "auth-session-state-"+state[:minInt(10, len(state))])
			require.NotEmpty(t, oauthSessionID)

			// Add a code to mark as complete
			code := generateSecureCode()
			err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
			require.NoError(t, err)

			// Check status to get redirect URL
			req := httptest.NewRequest("GET", "/oauth/session/"+oauthSessionID+"/status", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp OAuthSessionStatusResponse
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)

			// Parse the redirect URL and verify state
			redirectURL, err := url.Parse(resp.RedirectURL)
			require.NoError(t, err)
			assert.Equal(t, state, redirectURL.Query().Get("state"), "state should be preserved exactly")
		})
	}
}

// TestOAuth_ConcurrentCodeExchange tests that concurrent code exchanges are handled correctly
func TestOAuth_ConcurrentCodeExchange(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a session with a code
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-concurrent")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	// Launch multiple concurrent requests
	const numRequests = 10
	var wg sync.WaitGroup
	results := make(chan int, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	wg.Wait()
	close(results)

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for statusCode := range results {
		if statusCode == http.StatusOK {
			successCount++
		} else {
			failureCount++
		}
	}

	// Only one request should succeed (first one to claim the code)
	assert.Equal(t, 1, successCount, "only one concurrent request should succeed")
	assert.Equal(t, numRequests-1, failureCount, "all other requests should fail")
}

// TestOAuth_FullFlow tests the complete OAuth authorization flow
func TestOAuth_FullFlow(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/authorize", srv.handleOAuthAuthorize)
	router.POST("/oauth/callback", srv.handleOAuthCallback)
	router.POST("/oauth/token", srv.handleOAuthToken)
	router.GET("/oauth/session/:id/status", srv.handleOAuthSessionStatus)

	// Enable mock login for testing
	srv.config.AllowMockLogin = true

	// Step 1: Start OAuth flow with authorize request
	state := "unique-state-value-12345"
	redirectURI := "http://localhost:3000/callback"

	q := url.Values{}
	q.Set("client_id", "explorer-app")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)

	req1 := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	// Parse the response
	var authorizeResp map[string]interface{}
	err := json.Unmarshal(w1.Body.Bytes(), &authorizeResp)
	require.NoError(t, err)

	oauthSessionID := authorizeResp["oauth_session_id"].(string)
	authSessionID := authorizeResp["auth_session_id"].(string)
	require.NotEmpty(t, oauthSessionID)
	require.NotEmpty(t, authSessionID)

	// Step 2: Simulate Privado authentication callback with mock token
	callbackBody := map[string]interface{}{
		"token": "mock.token.did:privado:test_user_123",
	}
	callbackBodyBytes, _ := json.Marshal(callbackBody)

	req2 := httptest.NewRequest("POST", "/oauth/callback?session="+authSessionID+"&oauth_session="+oauthSessionID, bytes.NewReader(callbackBodyBytes))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var callbackResp map[string]interface{}
	err = json.Unmarshal(w2.Body.Bytes(), &callbackResp)
	require.NoError(t, err)
	assert.Equal(t, "success", callbackResp["status"])

	// Extract code from redirect URL
	callbackRedirectURL, err := url.Parse(callbackResp["redirect_url"].(string))
	require.NoError(t, err)
	authCode := callbackRedirectURL.Query().Get("code")
	require.NotEmpty(t, authCode)
	assert.Equal(t, state, callbackRedirectURL.Query().Get("state"))

	// Step 3: Exchange authorization code for tokens
	tokenRequest := OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        authCode,
		RedirectURI: redirectURI,
		ClientID:    "explorer-app",
	}
	tokenReqBody, _ := json.Marshal(tokenRequest)

	req3 := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(tokenReqBody))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	assert.Equal(t, http.StatusOK, w3.Code)

	var tokenResp OAuthTokenResponse
	err = json.Unmarshal(w3.Body.Bytes(), &tokenResp)
	require.NoError(t, err)

	// Verify token response
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
	assert.Greater(t, tokenResp.ExpiresIn, 0)

	// Validate the JWT
	claims, err := srv.jwtService.ValidateAccessToken(tokenResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "did:privado:test_user_123", claims.Subject)
}

// TestOAuth_SessionStoreCapacity tests the session store capacity limits
func TestOAuth_SessionStoreCapacity(t *testing.T) {
	// Create a store with very low capacity
	store := NewOAuthSessionStore(10*time.Minute, 1*time.Hour, 3)
	defer store.Stop()

	// Create sessions up to capacity
	for i := 0; i < 3; i++ {
		sessionID := store.CreateSession("client", "http://localhost/callback", fmt.Sprintf("state-%d", i), fmt.Sprintf("auth-%d", i))
		assert.NotEmpty(t, sessionID, "should create session %d", i)
	}

	// Try to create one more - should fail
	sessionID := store.CreateSession("client", "http://localhost/callback", "state-overflow", "auth-overflow")
	assert.Empty(t, sessionID, "should not create session beyond capacity")
}

// TestOAuthSessionStore_Cleanup tests that expired sessions are cleaned up
func TestOAuthSessionStore_Cleanup(t *testing.T) {
	// Create a store with very short TTL and cleanup interval
	store := NewOAuthSessionStore(50*time.Millisecond, 100*time.Millisecond, 100)
	defer store.Stop()

	// Create a session
	sessionID := store.CreateSession("client", "http://localhost/callback", "state", "auth")
	require.NotEmpty(t, sessionID)

	// Verify session exists
	session := store.GetSession(sessionID)
	require.NotNil(t, session)

	// Wait for expiration and cleanup
	time.Sleep(200 * time.Millisecond)

	// Verify session is gone
	session = store.GetSession(sessionID)
	assert.Nil(t, session, "expired session should be cleaned up")
}

// TestOAuthSessionStore_CodeIndex tests that code index is properly maintained
func TestOAuthSessionStore_CodeIndex(t *testing.T) {
	store := NewOAuthSessionStore(10*time.Minute, 1*time.Hour, 100)
	defer store.Stop()

	// Create session and set code
	sessionID := store.CreateSession("client", "http://localhost/callback", "state", "auth")
	require.NotEmpty(t, sessionID)

	code := "test-code-12345"
	err := store.SetCode(sessionID, code, "did:user:123", true)
	require.NoError(t, err)

	// Should be able to retrieve by code
	session := store.GetSessionByCode(code)
	require.NotNil(t, session)
	assert.Equal(t, "did:user:123", session.UserDID)

	// Delete session and verify code index is cleaned up
	store.DeleteSession(sessionID)

	session = store.GetSessionByCode(code)
	assert.Nil(t, session, "code index should be cleaned up after session deletion")
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
