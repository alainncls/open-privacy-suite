package main

// Proof generation + JWZ packing.
//
// Phase 1b (RD-947): `prepareAuthV2Inputs` now produces the same shape that
// `go-circuits/v2/authV2.AuthV2Inputs.InputsMarshal` consumes — wallet-side
// equivalent of what the Privado mobile app does.
//
// References:
//   - github.com/iden3/go-circuits/v2/authV2.go     (AuthV2Inputs struct)
//   - github.com/iden3/go-circuits/v2/authV2_test.go (canonical wiring)
//   - github.com/iden3/go-jwz/v2/authV2Groth16.go    (challenge = SetBytes(msgHash))

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	circuits "github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
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
// identity into the JSON inputs the auth-v2 circuit consumes.
//
// What we rebuild here (mirrors identity.go:identityInit deterministically
// so the on-chain registered state still matches):
//
//   - The wallet's BabyJubJub keypair, from idf.BabyJub.PrivateKey.
//   - The Auth claim (schema = core.AuthSchemaHash, index data = pub.X/Y).
//   - The three trees: claims (one leaf — the Auth claim), revocations
//     (empty), roots (empty).
//   - Inclusion proof of the Auth claim in the claims tree, non-revocation
//     proof in the revocations tree (proof of non-existence of revNonce=0).
//   - TreeState (claims/rev/roots roots + Poseidon(state) over the three).
//   - GISTProof — fetched on-chain from the Privado state contract via
//     `fetchGISTProof` (see gist.go). The contract returns the inclusion
//     (or non-inclusion) proof of this identity in the global identity
//     state tree.
//   - Signature — BabyJub Poseidon signature of the JWZ challenge.
//   - Challenge — *big.Int interpretation of the hash bytes; matches what
//     ProvingMethodGroth16AuthV2.Verify compares against
//     (see go-jwz authV2Groth16.go:Verify "new(big.Int).SetBytes(messageHash)").
func prepareAuthV2Inputs(idf *IdentityFile, hash []byte, did *w3c.DID, circuitID circuits.CircuitID) ([]byte, error) {
	// Sanity: confirm the circuit ID we get matches what we registered.
	if circuitID != circuits.AuthV2CircuitID {
		return nil, fmt.Errorf("unexpected circuit ID %q (want %q)", circuitID, circuits.AuthV2CircuitID)
	}
	if did == nil {
		return nil, fmt.Errorf("nil DID passed to data preparer")
	}

	// 1. Re-derive the BabyJub keypair from the persisted private seed.
	rawPriv, err := hex.DecodeString(idf.BabyJub.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(rawPriv) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(rawPriv))
	}
	var priv babyjub.PrivateKey
	copy(priv[:], rawPriv)
	pub := priv.Public()

	// 2. Rebuild the Auth claim — the exact same call identityInit makes.
	// core.AuthSchemaHash is the canonical schema hash for auth claims; using
	// it here keeps the claim hash deterministic across identity init and
	// auth runs (otherwise the inclusion proof would not match).
	authClaim, err := core.NewClaim(
		core.AuthSchemaHash,
		core.WithIndexDataInts(pub.X, pub.Y),
		core.WithRevocationNonce(0),
	)
	if err != nil {
		return nil, fmt.Errorf("rebuild auth claim: %w", err)
	}

	// 3. Rebuild the three trees and add the Auth claim to the claims tree.
	// Tree depth 32 must match what identityInit used (otherwise the roots
	// differ and the on-chain state mismatches what we have here).
	ctx := emptyContext()
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		return nil, fmt.Errorf("claims tree: %w", err)
	}
	hi, hv, err := authClaim.HiHv()
	if err != nil {
		return nil, fmt.Errorf("auth claim hi/hv: %w", err)
	}
	if err := claimsTree.Add(ctx, hi, hv); err != nil {
		return nil, fmt.Errorf("add auth claim to claims tree: %w", err)
	}
	revTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		return nil, fmt.Errorf("revocation tree: %w", err)
	}
	rootsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		return nil, fmt.Errorf("roots tree: %w", err)
	}

	// 4. Compute the genesis state from the three roots.
	stateBI, err := poseidon.Hash([]*big.Int{
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		rootsTree.Root().BigInt(),
	})
	if err != nil {
		return nil, fmt.Errorf("compute state: %w", err)
	}
	stateHash, err := merkletree.NewHashFromBigInt(stateBI)
	if err != nil {
		return nil, fmt.Errorf("state hash: %w", err)
	}

	// 5. Inclusion proof of the Auth claim in the claims tree, and
	// non-revocation proof (proof that revNonce=0 is NOT in revocations).
	authIncMtp, _, err := claimsTree.GenerateProof(ctx, hi, claimsTree.Root())
	if err != nil {
		return nil, fmt.Errorf("auth claim inclusion proof: %w", err)
	}
	authNonRevMtp, _, err := revTree.GenerateProof(ctx, big.NewInt(0), revTree.Root())
	if err != nil {
		return nil, fmt.Errorf("auth claim non-revocation proof: %w", err)
	}

	treeState := circuits.TreeState{
		State:          stateHash,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	// 6. Resolve the wallet's core.ID from the DID passed by the packer
	// AND from the persisted file; assert they match. If they differ, the
	// JWZ packer is operating on a DID the user did not authorize — bail.
	idFromDID, err := core.IDFromDID(*did)
	if err != nil {
		return nil, fmt.Errorf("derive ID from packer DID: %w", err)
	}
	walletDID, err := w3c.ParseDID(idf.DID)
	if err != nil {
		return nil, fmt.Errorf("parse wallet DID from identity file: %w", err)
	}
	if !idMatchesDID(&idFromDID, walletDID) {
		return nil, fmt.Errorf("DID/ID mismatch between identity file and packer (file=%s, packer=%s)", idf.DID, did.String())
	}

	// 7. Fetch the on-chain gist proof for this ID against the Privado
	// state contract. Env-overridable for staging / local testing.
	rpcURL := os.Getenv("PRIVADO_RPC_URL")
	if rpcURL == "" {
		rpcURL = defaultPrivadoRPCURL
	}
	stateContract := os.Getenv("PRIVADO_STATE_CONTRACT")
	if stateContract == "" {
		stateContract = defaultPrivadoStateContract
	}
	gistProof, err := fetchGISTProof(ctx, rpcURL, stateContract, idFromDID.BigInt())
	if err != nil {
		return nil, fmt.Errorf("fetch gist proof from %s: %w", stateContract, err)
	}

	// 8. BabyJub Poseidon signature over the challenge. The proxy verifier
	// (go-jwz authV2Groth16.go:Verify) compares Challenge against
	// new(big.Int).SetBytes(messageHash), so we sign the same value here.
	challenge := new(big.Int).SetBytes(hash)
	signature := priv.SignPoseidon(challenge)

	inputs := circuits.AuthV2Inputs{
		GenesisID:          &idFromDID,
		ProfileNonce:       big.NewInt(0),
		AuthClaim:          authClaim,
		AuthClaimIncMtp:    authIncMtp,
		AuthClaimNonRevMtp: authNonRevMtp,
		TreeState:          treeState,
		GISTProof:          gistProof,
		Signature:          signature,
		Challenge:          challenge,
	}

	return inputs.InputsMarshal()
}

// idMatchesDID is a defensive helper: the auth-v2 input prep must use
// the same ID the JWZ packer signed for, otherwise FullVerify will
// reject.
func idMatchesDID(id *core.ID, did *w3c.DID) bool {
	parsed, err := core.IDFromDID(*did)
	if err != nil {
		return false
	}
	return parsed.Equal(id)
}
