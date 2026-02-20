package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// generateAPIKey creates a new API key with the ppk_ prefix.
// Returns (plaintext_key, sha256_hash, error).
func generateAPIKey() (string, string, error) {
	// Generate 32 random bytes
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	rawKey := "ppk_" + hex.EncodeToString(b)
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	return rawKey, keyHash, nil
}

// generateUUID returns a new UUID string.
func generateUUID() string {
	return uuid.New().String()
}
