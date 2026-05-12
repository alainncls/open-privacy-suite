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
//
// L5 (security audit): the middleware previously trusted CheckAccess
// downstream to enforce the banned-user check. That made the property
// "no banned user can act through this proxy" depend on every JSON-RPC
// consumer piping through CheckAccess — easy to silently regress when
// a future feature reuses OptionalJWT for a new endpoint. Now Banned
// is enforced here when the RevocationChecker also implements the
// BannedChecker extension; the regular *db.DB satisfies both so the
// production path is upgraded automatically. Implementations that
// only satisfy RevocationChecker (test fixtures) keep the previous
// behaviour.
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
			if banChk, ok := db.(BannedChecker); ok {
				banned, err := banChk.IsUserBannedBySubject(c.Request.Context(), claims.Subject)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check user ban status"})
					c.Abort()
					return
				}
				if banned {
					c.JSON(http.StatusForbidden, gin.H{"error": "user is banned"})
					c.Abort()
					return
				}
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

// BannedChecker is an optional extension to RevocationChecker that
// lets OptionalJWTAuthMiddleware enforce user bans at the auth
// boundary. The production *db.DB type implements it; test fixtures
// that don't are not affected.
type BannedChecker interface {
	IsUserBannedBySubject(ctx context.Context, subject string) (bool, error)
}

// getTokenID generates a hash ID from token string for revocation tracking
func getTokenID(tokenString string) string {
	hash := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(hash[:])
}
