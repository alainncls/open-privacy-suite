package auth

import (
	"context"
	"fmt"

	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"
)

// PrivadoVerifier handles verification of Privado ID JWZ proofs
type PrivadoVerifier struct {
	verifier *auth.Verifier
}

// NewPrivadoVerifier creates a new Privado ID verifier
// For Privado mainnet, uses the common state contract
func NewPrivadoVerifier(rpcURL, ipfsGateway string) (*PrivadoVerifier, error) {
	// Privado mainnet state contract address (common address for Ethereum, Privado, Linea, zkEVM)
	const PRIVADO_STATE_ADDRESS = "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"

	// Create state resolver for Privado network
	resolver := state.NewETHResolver(rpcURL, PRIVADO_STATE_ADDRESS)
	resolvers := map[string]pubsignals.StateResolver{
		"privado:main": resolver,
	}

	// Use embedded keys for verification (included in the library)
	keyLoader := loaders.NewEmbeddedKeyLoader()
	
	// Use provided IPFS gateway (or default)
	ipfsGW := ipfsGateway
	if ipfsGW == "" {
		ipfsGW = "https://ipfs-proxy-cache.privado.id"
	}

	// Create verifier with IPFS gateway option (not schema loader)
	// Based on offchain_verifier implementation: auth.NewVerifier(keyLoader, resolvers, auth.WithIPFSGateway(ipfsGW))
	verifier, err := auth.NewVerifier(keyLoader, resolvers, auth.WithIPFSGateway(ipfsGW))
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}
	if verifier == nil {
		return nil, fmt.Errorf("verifier is nil")
	}

	return &PrivadoVerifier{
		verifier: verifier,
	}, nil
}

// CreateAuthorizationRequest creates a Privado ID authorization request
// verifierID: The DID or identifier of the verifier (your service)
// callbackURL: Where the wallet should send the proof response
// reason: Human-readable reason for the request
func (p *PrivadoVerifier) CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error) {
	// Create basic authorization request
	// This requests proof of identity (DID ownership)
	reqMsg := auth.CreateAuthorizationRequest(reason, verifierID, callbackURL)
	
	// Optionally add KYC proof requirement
	// For now, we'll use basic auth (just DID proof)
	// You can extend this to require specific credentials by adding to reqMsg.Body.Scope
	
	return &reqMsg, nil
}

// VerifyJWZ verifies a Privado ID JWZ token against an authorization request
// Returns the user's DID (Decentralized Identifier) if verification succeeds
// authRequest: The original authorization request that was sent to the user
// verifierID: The expected verifier ID (should match authResponse.To)
func (p *PrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
	if p.verifier == nil {
		return "", fmt.Errorf("verifier not initialized")
	}

	if authRequest == nil {
		return "", fmt.Errorf("authorization request is required")
	}

	// Verify the JWZ token against the original authorization request
	// This ensures the proof matches what was requested
	authResponse, err := p.verifier.FullVerify(
		ctx,
		jwzToken,
		*authRequest,
	)
	if err != nil {
		return "", fmt.Errorf("JWZ verification failed: %w", err)
	}

	// Security check: Verify that the proof was generated for our verifier ID
	// The authResponse.To field should match our verifier ID
	// This prevents accepting proofs intended for other verifiers
	if verifierID != "" && authResponse.To != verifierID {
		return "", fmt.Errorf("verifier ID mismatch: proof intended for %s, but expected %s", authResponse.To, verifierID)
	}

	// Extract user DID from the verified response
	// authResponse.From contains the DID of the user who generated the proof
	userDID := authResponse.From
	if userDID == "" {
		return "", fmt.Errorf("user DID not found in verified response")
	}

	return userDID, nil
}
