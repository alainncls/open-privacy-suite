package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTService_IssueAccessToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_ValidateAccessToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a token
	subject := "did:privado:test123"
	kyc := true
	token, err := service.IssueAccessToken(subject, kyc)
	require.NoError(t, err)

	// Validate the token
	claims, err := service.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.Equal(t, subject, claims.Subject)
	assert.Equal(t, kyc, claims.KYC)
	assert.True(t, claims.ExpiresAt.Time.After(time.Now()))
}

func TestJWTService_ValidateAccessToken_Expired(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", -1*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue an expired token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	// Validation should fail
	_, err = service.ValidateAccessToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestJWTService_ValidateAccessToken_Invalid(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Try to validate an invalid token
	_, err = service.ValidateAccessToken("invalid.token.here")
	assert.Error(t, err)
	// Check if error is ErrInvalidToken (using errors.Is for wrapped errors)
	assert.ErrorIs(t, err, ErrInvalidToken, "error should be or wrap ErrInvalidToken")
}

func TestJWTService_IssueRefreshToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := service.IssueRefreshToken("did:privado:test123")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_ValidateRefreshToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a refresh token
	subject := "did:privado:test123"
	token, err := service.IssueRefreshToken(subject)
	require.NoError(t, err)

	// Validate the token
	claims, err := service.ValidateRefreshToken(token)
	require.NoError(t, err)
	assert.Equal(t, subject, claims.Subject)
	assert.True(t, claims.ExpiresAt.Time.After(time.Now()))
}

func TestJWTService_ValidateRefreshToken_WrongSecret(t *testing.T) {
	service1, err := NewJWTService("secret1", "refresh-secret1", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	service2, err := NewJWTService("secret2", "refresh-secret2", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue token with service1
	token, err := service1.IssueRefreshToken("did:privado:test123")
	require.NoError(t, err)

	// Try to validate with service2 (different secret)
	_, err = service2.ValidateRefreshToken(token)
	assert.Error(t, err)
}

func TestHashToken(t *testing.T) {
	token := "test-token-123"
	hash1 := HashToken(token)
	hash2 := HashToken(token)

	// Same token should produce same hash
	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 64) // SHA256 produces 64 hex characters

	// Different token should produce different hash
	hash3 := HashToken("different-token")
	assert.NotEqual(t, hash1, hash3)
}
