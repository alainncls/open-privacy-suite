package auth

import (
	"context"
	"encoding/json"
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

// CreateHumanityAuthRequest creates a Privado ID authorization request with ProofOfHumanity ZK query
// This requires the user to prove they have a valid ProofOfHumanity credential from the specified issuer
func (p *PrivadoVerifier) CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string) (*protocol.AuthorizationRequestMessage, error) {
	// Create basic authorization request
	reqMsg := auth.CreateAuthorizationRequest(reason, verifierID, callbackURL)

	// Add ProofOfHumanity ZK query to scope
	// This requires the user to prove they have a ProofOfHumanity credential with isHuman=1
	mtpProofRequest := protocol.ZeroKnowledgeProofRequest{
		ID:        1,
		CircuitID: "credentialAtomicQueryMTPV2",
		Query: map[string]interface{}{
			"allowedIssuers": []string{issuerDID},
			"credentialSubject": map[string]interface{}{
				"isHuman": map[string]interface{}{
					"$eq": 1,
				},
			},
			"context": "https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/main/credential-schema/schemas-examples/proof-of-humanity/proof-of-humanity.jsonld",
			"type":    "ProofOfHumanity",
		},
	}
	reqMsg.Body.Scope = append(reqMsg.Body.Scope, mtpProofRequest)

	return &reqMsg, nil
}

// VerificationResult contains the results of JWZ verification
type VerificationResult struct {
	// UserDID is the decentralized identifier of the user who generated the proof
	UserDID string
	// ProofData contains the credential subject data from verified ZK proofs
	// Each entry in the slice corresponds to a ZeroKnowledgeProofResponse from the scope
	ProofData []map[string]any
}

// VerifyJWZ verifies a Privado ID JWZ token against an authorization request
// Returns the user's DID (Decentralized Identifier) if verification succeeds
// authRequest: The original authorization request that was sent to the user
// verifierID: The expected verifier ID (should match authResponse.To)
func (p *PrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
	result, err := p.VerifyJWZWithProofData(ctx, jwzToken, authRequest, verifierID)
	if err != nil {
		return "", err
	}
	return result.UserDID, nil
}

// VerifyJWZWithProofData verifies a Privado ID JWZ token and returns both the user DID and proof data
// This extended version allows extraction of ZK-attested claims from the credential proofs
func (p *PrivadoVerifier) VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*VerificationResult, error) {
	if p.verifier == nil {
		return nil, fmt.Errorf("verifier not initialized")
	}

	if authRequest == nil {
		return nil, fmt.Errorf("authorization request is required")
	}

	// Verify the JWZ token against the original authorization request
	// This ensures the proof matches what was requested
	authResponse, err := p.verifier.FullVerify(
		ctx,
		jwzToken,
		*authRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("JWZ verification failed: %w", err)
	}

	// Security check: Verify that the proof was generated for our verifier ID
	// The authResponse.To field should match our verifier ID
	// This prevents accepting proofs intended for other verifiers
	if verifierID != "" && authResponse.To != verifierID {
		return nil, fmt.Errorf("verifier ID mismatch: proof intended for %s, but expected %s", authResponse.To, verifierID)
	}

	// Extract user DID from the verified response
	// authResponse.From contains the DID of the user who generated the proof
	userDID := authResponse.From
	if userDID == "" {
		return nil, fmt.Errorf("user DID not found in verified response")
	}

	// Extract proof data from the scope (ZK proof responses)
	// Each proof in the scope contains credential data that may include role claims
	var proofData []map[string]any
	for _, zkProof := range authResponse.Body.Scope {
		data := make(map[string]any)

		// Add proof ID for reference
		data["id"] = zkProof.ID
		data["circuitID"] = zkProof.CircuitID

		// Extract verifiable presentation data if available
		if len(zkProof.VerifiablePresentation) > 0 {
			var vp map[string]any
			if err := json.Unmarshal(zkProof.VerifiablePresentation, &vp); err == nil {
				// Look for credentialSubject in the verifiable presentation
				if credSubject, ok := vp["credentialSubject"].(map[string]any); ok {
					data["credentialSubject"] = credSubject
				}
				// Also include the full VP for any other claims
				data["verifiablePresentation"] = vp
			}
		}

		// Extract public signals from the ZK proof which may contain credential data
		if zkProof.PubSignals != nil {
			data["pubSignals"] = zkProof.PubSignals
		}

		proofData = append(proofData, data)
	}

	return &VerificationResult{
		UserDID:   userDID,
		ProofData: proofData,
	}, nil
}
