package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// JWTAuthMiddleware validates JWT access tokens
func JWTAuthMiddleware(jwtService *JWTService, db RevocationChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			c.Abort()
			return
		}

		// Parse Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			if err == ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			c.Abort()
			return
		}

		// Check if token is revoked (if revocation checker is available)
		if db != nil {
			// Use hash of token as ID for revocation tracking
			tokenID := getTokenID(tokenString)
			revoked, err := db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check token revocation"})
				c.Abort()
				return
			}
			if revoked {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
				c.Abort()
				return
			}
		}

		// Store claims in context for use in handlers
		c.Set("subject", claims.Subject)
		c.Set("kyc", claims.KYC)
		c.Set("claims", claims)

		c.Next()
	}
}

// OptionalJWTAuthMiddleware validates JWT if present, but allows anonymous requests.
func OptionalJWTAuthMiddleware(jwtService *JWTService, db RevocationChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			// If header is malformed, we still fail (security measure)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			// If token is invalid/expired, we fail (security measure)
			if err == ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			c.Abort()
			return
		}

		if db != nil {
			tokenID := getTokenID(tokenString)
			revoked, err := db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check token revocation"})
				c.Abort()
				return
			}
			if revoked {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
				c.Abort()
				return
			}
		}

		c.Set("subject", claims.Subject)
		c.Set("kyc", claims.KYC)
		c.Set("claims", claims)

		c.Next()
	}
}

// RevocationChecker interface for checking token revocation
type RevocationChecker interface {
	IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error)
}

// OptionalJWTAuthMiddleware validates JWT if present, but allows anonymous requests.
func OptionalJWTAuthMiddleware(jwtService *JWTService, db RevocationChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			if err == ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			c.Abort()
			return
		}

		if db != nil {
			tokenID := getTokenID(tokenString)
			revoked, err := db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check token revocation"})
				c.Abort()
				return
			}
			if revoked {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
				c.Abort()
				return
			}
		}

		c.Set("subject", claims.Subject)
		c.Set("kyc", claims.KYC)
		c.Set("claims", claims)

		c.Next()
	}
}

// getTokenID generates a hash ID from token string for revocation tracking
func getTokenID(tokenString string) string {
	hash := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(hash[:])
}
