package auth

import (
	"context"
	"fmt"

	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	auth "github.com/iden3/go-iden3-auth/v2"
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

// VerifyJWZ verifies a Privado ID JWZ token
// Returns the user's DID (Decentralized Identifier) if verification succeeds
// Note: Unlike offchain_verifier which creates a request, here we verify a predefined JWZ token
// The JWZ token should contain a proof that the user has KYC passed
func (p *PrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string) (string, error) {
	if p.verifier == nil {
		return "", fmt.Errorf("verifier not initialized")
	}

	// Create an empty authorization request for verification
	// Since we're verifying a predefined scheme (KYC), we don't need to match against
	// a specific request - the JWZ token itself contains the proof structure
	emptyRequest := protocol.AuthorizationRequestMessage{}

	// Verify the JWZ token
	// This performs:
	// 1. JWZ token verification
	// 2. Zero-knowledge proof verification
	// 3. Query request verification (if request is provided)
	// 4. Identity and issuer state verification
	authResponse, err := p.verifier.FullVerify(
		ctx,
		jwzToken,
		emptyRequest,
	)
	if err != nil {
		return "", fmt.Errorf("JWZ verification failed: %w", err)
	}

	// Extract user DID from the verified response
	// authResponse.From contains the DID of the user who generated the proof
	userDID := authResponse.From
	if userDID == "" {
		return "", fmt.Errorf("user DID not found in verified response")
	}

	return userDID, nil
}
