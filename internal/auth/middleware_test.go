package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRevocationChecker implements RevocationChecker for testing
type mockRevocationChecker struct {
	revokedTokens map[string]bool
}

func (m *mockRevocationChecker) IsAccessTokenRevoked(_ context.Context, tokenID string) (bool, error) {
	return m.revokedTokens[tokenID], nil
}

func TestJWTAuthMiddleware_ValidToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	// Setup router with middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		subject, _ := c.Get("subject")
		kyc, _ := c.Get("kyc")
		c.JSON(http.StatusOK, gin.H{
			"subject": subject,
			"kyc":     kyc,
		})
	})

	// Make request with valid token
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuthMiddleware_MissingHeader(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_ExpiredToken(t *testing.T) {
	// Create service with negative TTL (expired immediately)
	service, err := NewJWTService("test-secret", "test-refresh-secret", -1*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue an expired token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_RevokedToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	// Create mock revocation checker with token revoked
	tokenID := getTokenID(token)
	mockDB := &mockRevocationChecker{
		revokedTokens: map[string]bool{
			tokenID: true,
		},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, mockDB), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
