package main

// Proof generation + JWZ packing.
//
// Phase 1 scaffolding (RD-947): the iden3comm ZKPPacker setup is here
// and complete; what's left is the `prepareAuthV2Inputs` function that
// converts the JWZ message hash + the wallet's identity into the JSON
// inputs the auth-v2 circuit expects. The hand-off is documented at
// each TODO with the precise iden3 type the caller must produce.

import (
	"encoding/json"
	"fmt"

	circuits "github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"

	"github.com/iden3/go-jwz/v2"
)

// packAuthResponse serialises an iden3comm AuthorizationResponseMessage
// addressed to the verifier (request.From) from the wallet (idf.DID),
// generates the auth-v2 ZK proof, and wraps the whole thing in a JWZ.
// Returns the JWZ envelope bytes ready to POST to /auth/verify.
func packAuthResponse(idf *IdentityFile, request *protocol.AuthorizationRequestMessage, wasm, provingKey []byte) ([]byte, error) {
	walletDID, err := w3c.ParseDID(idf.DID)
	if err != nil {
		return nil, fmt.Errorf("parse wallet DID %q: %w", idf.DID, err)
	}

	// Build the authorization response. The body's scope echoes back
	// the proof requests from the original auth request — for the basic
	// "prove DID ownership" flow there is no scope, just the
	// challenge-signing proof embedded in the JWZ envelope itself.
	response := protocol.AuthorizationResponseMessage{
		ID:       request.ID,
		Typ:      packers.MediaTypeZKPMessage,
		Type:     protocol.AuthorizationResponseMessageType,
		ThreadID: request.ThreadID,
		From:     walletDID.String(),
		To:       request.From,
		Body: protocol.AuthorizationMessageResponseBody{
			Message: request.Body.Message,
			Scope:   []protocol.ZeroKnowledgeProofResponse{},
		},
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	// Set up the ZKPPacker with the auth-v2 proving method. The
	// DataPreparer translates the JWZ message hash into the JSON inputs
	// the auth-v2 circuit expects — see `prepareAuthV2Inputs` below.
	provingParams := map[jwz.ProvingMethodAlg]packers.ProvingParams{
		jwz.AuthV2Groth16Alg: packers.NewProvingParams(
			packers.DataPreparerHandlerFunc(func(hash []byte, id *w3c.DID, circuitID circuits.CircuitID) ([]byte, error) {
				return prepareAuthV2Inputs(idf, hash, id, circuitID)
			}),
			provingKey,
			wasm,
		),
	}
	packer := packers.NewZKPPacker(provingParams, nil)

	packed, err := packer.Pack(payload, packers.ZKPPackerParams{
		SenderID:         walletDID,
		ProvingMethodAlg: jwz.AuthV2Groth16Alg,
	})
	if err != nil {
		return nil, fmt.Errorf("ZKPPacker.Pack: %w", err)
	}
	return packed, nil
}

// Compile-time assertion that we're still using a known protocol media
// type. If this stops compiling after an iden3comm bump, the surrounding
// code probably needs updating too.
var _ = iden3comm.MediaType(packers.MediaTypeZKPMessage)

// prepareAuthV2Inputs converts the JWZ message hash + the wallet's
// identity into the JSON inputs the auth-v2 circuit consumes. This is
// the meat of the Phase 1b follow-up.
//
// The auth-v2 circuit (see go-circuits/v2:AuthV2Inputs) wants:
//
//   - The genesis identity ID + current state.
//   - The Auth claim itself + its Merkle inclusion proof in the
//     claims tree.
//   - The non-revocation proof from the revocations tree (empty for
//     a fresh identity).
//   - A BabyJubJub signature of the challenge (= hash) by the
//     wallet's private key.
//   - The gist-tree proof showing the identity's state is present on
//     the on-chain state contract.
//
// All but the last two are reproducible from the identity file alone;
// the gist proof requires an RPC round-trip to the state contract.
// That fetcher is the substantive piece this stub leaves out.
//
// References for the implementation:
//
//   - github.com/iden3/go-circuits/v2/authV2.go:AuthV2Inputs.InputsMarshal
//   - github.com/iden3/go-iden3-auth/v2 examples/wallet_test.go in upstream
//   - github.com/iden3/go-rapidsnark/witness for witness gen wiring.
func prepareAuthV2Inputs(idf *IdentityFile, hash []byte, did *w3c.DID, circuitID circuits.CircuitID) ([]byte, error) {
	_ = idf
	_ = hash
	_ = did
	_ = circuitID
	// Sanity: confirm the circuit ID we get matches what we registered.
	if circuitID != circuits.AuthV2CircuitID {
		return nil, fmt.Errorf("unexpected circuit ID %q (want %q)", circuitID, circuits.AuthV2CircuitID)
	}
	return nil, fmt.Errorf("auth-v2 input preparation not yet implemented (RD-947 Phase 1b — see proof.go header)")
}

// idMatchesDID is a defensive helper: the auth-v2 input prep must use
// the same ID the JWZ packer signed for, otherwise FullVerify will
// reject. Kept here so the Phase 1b implementation has the assertion
// already wired.
func idMatchesDID(id *core.ID, did *w3c.DID) bool {
	parsed, err := core.IDFromDID(*did)
	if err != nil {
		return false
	}
	return parsed.Equal(id)
}

// Compile-time use of idMatchesDID until Phase 1b wires it.
var _ = idMatchesDID
