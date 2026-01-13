package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

// JWTService handles JWT token issuance and validation
type JWTService struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// TokenClaims represents the claims in our JWT tokens
type TokenClaims struct {
	Subject string `json:"sub"` // User DID from Privado ID
	KYC     bool   `json:"kyc"` // KYC status (from verified proof)
	jwt.RegisteredClaims
}

// NewJWTService creates a new JWT service
// For production, secrets should be loaded from secure configuration
func NewJWTService(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) (*JWTService, error) {
	if accessSecret == "" {
		// Generate a random secret if not provided (for development only)
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate secret: %w", err)
		}
		accessSecret = base64.URLEncoding.EncodeToString(secret)
	}

	if refreshSecret == "" {
		// Generate a random secret if not provided (for development only)
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate refresh secret: %w", err)
		}
		refreshSecret = base64.URLEncoding.EncodeToString(secret)
	}

	return &JWTService{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}, nil
}

// IssueAccessToken issues a new access token (short-lived)
func (j *JWTService) IssueAccessToken(subject string, kyc bool) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		Subject: subject,
		KYC:     kyc,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique token ID
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.accessSecret)
}

// IssueRefreshToken issues a new refresh token (long-lived, stored in DB)
func (j *JWTService) IssueRefreshToken(subject string) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		Subject: subject,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique token ID for refresh token rotation
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.refreshSecret)
}

// HashToken creates a hash of a token for storage (for refresh tokens)
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// ValidateAccessToken validates an access token and returns the claims
func (j *JWTService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	return j.validateToken(tokenString, j.accessSecret)
}

// ValidateRefreshToken validates a refresh token and returns the claims
func (j *JWTService) ValidateRefreshToken(tokenString string) (*TokenClaims, error) {
	return j.validateToken(tokenString, j.refreshSecret)
}

func (j *JWTService) validateToken(tokenString string, secret []byte) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		// Wrap ErrInvalidToken so errors.Is works correctly
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
