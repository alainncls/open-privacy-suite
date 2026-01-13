package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/access"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPrivadoVerifier is a mock for testing (implements PrivadoVerifier interface)
type mockPrivadoVerifier struct {
	verifyFunc func(ctx context.Context, jwzToken string) (string, error)
}

func (m *mockPrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string) (string, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, jwzToken)
	}
	return "did:privado:test123", nil
}

func setupTestServerForAuth(t *testing.T) (*Server, *auth.JWTService) {
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

	// Clean up tables
	database.Conn().Exec("DROP TABLE IF EXISTS access_logs")
	database.Conn().Exec("DROP TABLE IF EXISTS access_policies")
	database.Conn().Exec("DROP TABLE IF EXISTS refresh_tokens")
	database.Conn().Exec("DROP TABLE IF EXISTS revoked_tokens")
	database.Migrate()

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
		verifyFunc: func(ctx context.Context, jwzToken string) (string, error) {
			// Mock: accept any JWZ token and return a test DID
			if jwzToken == "" {
				return "", fmt.Errorf("empty JWZ token")
			}
			return "did:privado:test123", nil
		},
	}

	srv := &Server{
		db:              database,
		privadoVerifier: mockVerifier,
		jwtService:      jwtService,
		accessCtrl:      access.NewController(database),
		proxy:           nil, // Not needed for auth tests
	}

	return srv, jwtService
}

func TestHandleAuth_Success(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth", srv.handleAuth)

	reqBody := map[string]interface{}{
		"jwz_token": "mock.jwz.token",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/auth", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, 1800, response.ExpiresIn)
}

func TestHandleAuth_InvalidRequest(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth", srv.handleAuth)

	req := httptest.NewRequest("POST", "/auth", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleAuth_VerificationFailure(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Update mock to return error
	mockVerifier := srv.privadoVerifier.(*mockPrivadoVerifier)
	mockVerifier.verifyFunc = func(ctx context.Context, jwzToken string) (string, error) {
		return "", fmt.Errorf("verification failed")
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth", srv.handleAuth)

	reqBody := map[string]interface{}{
		"jwz_token": "invalid.token",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/auth", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRefresh_Success(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue a refresh token
	subject := "did:privado:test123"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	// Save refresh token to DB
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(tokenHash, subject, expiresAt)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AuthResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	// Should be a new refresh token (rotated)
	assert.NotEqual(t, refreshToken, response.RefreshToken)
}

func TestHandleRefresh_InvalidToken(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody := map[string]interface{}{
		"refresh_token": "invalid.token",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRefresh_RevokedToken(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue and save refresh token
	subject := "did:privado:test123"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(tokenHash, subject, expiresAt)
	require.NoError(t, err)

	// Revoke the token
	err = srv.db.RevokeRefreshToken(tokenHash)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRevoke_Success(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue and save refresh token
	subject := "did:privado:test123"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(tokenHash, subject, expiresAt)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/revoke", srv.handleRevoke)

	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify token is revoked
	token, err := srv.db.GetRefreshToken(tokenHash)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.True(t, token.Revoked)
}
