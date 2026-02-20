package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/compliance"
)

// APIKeyStore defines the database operations needed by the API key middleware.
type APIKeyStore interface {
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*compliance.APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id string) error
}

// apiKeyMiddleware returns a Gin middleware that authenticates requests via API key.
// Keys are expected in the Authorization header as "Bearer ppk_<key>".
// The middleware checks that the key is valid, not revoked, not expired,
// and has the required permission.
func apiKeyMiddleware(store APIKeyStore, requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			c.Abort()
			return
		}

		// Extract bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			c.Abort()
			return
		}

		rawKey := parts[1]
		if !strings.HasPrefix(rawKey, "ppk_") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid API key format"})
			c.Abort()
			return
		}

		// Hash the key and look up
		hash := sha256.Sum256([]byte(rawKey))
		keyHash := hex.EncodeToString(hash[:])

		apiKey, err := store.GetAPIKeyByHash(c.Request.Context(), keyHash)
		if err != nil {
			log.Printf("ERROR: API key lookup failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			c.Abort()
			return
		}
		if apiKey == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			c.Abort()
			return
		}

		// Check revoked
		if apiKey.RevokedAt != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key has been revoked"})
			c.Abort()
			return
		}

		// Check expired
		if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key has expired"})
			c.Abort()
			return
		}

		// Check permission
		hasPermission := false
		for _, p := range apiKey.Permissions {
			if p == requiredPermission {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": "API key lacks required permission: " + requiredPermission})
			c.Abort()
			return
		}

		// Update last_used_at asynchronously
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := store.UpdateAPIKeyLastUsed(ctx, apiKey.ID); err != nil {
				log.Printf("WARNING: failed to update API key last_used_at: %v", err)
			}
		}()

		// Set API key info in context for downstream handlers
		c.Set("api_key_id", apiKey.ID)
		c.Set("api_key_name", apiKey.Name)

		c.Next()
	}
}
