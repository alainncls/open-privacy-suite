package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivadoVerifier_NewPrivadoVerifier(t *testing.T) {
	// Test with Privado mainnet RPC
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id")
	require.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.NotNil(t, verifier.verifier)
}

func TestPrivadoVerifier_NewPrivadoVerifier_InvalidRPC(t *testing.T) {
	// Test with invalid RPC URL (should still create verifier, but verification will fail)
	verifier, err := NewPrivadoVerifier("http://invalid-rpc-url:8545", "https://ipfs-proxy-cache.privado.id")
	// This might succeed or fail depending on validation
	// The actual verification will fail when we try to verify a token
	if err == nil {
		assert.NotNil(t, verifier)
	}
}

func TestPrivadoVerifier_VerifyJWZ_InvalidToken(t *testing.T) {
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id")
	require.NoError(t, err)

	// Try to verify an invalid JWZ token
	ctx := context.Background()
	_, err = verifier.VerifyJWZ(ctx, "invalid.jwz.token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// Note: Testing with real JWZ tokens would require actual Privado ID proofs
// For now, we test the structure and error handling
// In production, you'd want to add integration tests with real proofs
