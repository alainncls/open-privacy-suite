package main

// Identity bootstrap. Phase 1 stores a BabyJubJub keypair plus the iden3
// Auth-claim derivation needed to authenticate against a Privado verifier.
//
// On-disk format (JSON, UTF-8, mode 0600):
//
//	{
//	  "version": 1,
//	  "did":     "did:iden3:privado:main:...",
//	  "babyjub": {
//	    "private_key": "<32-byte hex>",
//	    "public_key":  ["<X big.Int dec>", "<Y big.Int dec>"]
//	  },
//	  "state":   "<32-byte hex, hex(genesis_state)>",
//	  "created_at": "2026-05-19T..."
//	}
//
// The genesis state and DID are derived deterministically from the public
// key + the iden3 Auth claim. Operators publish the state on-chain once,
// then reuse the file forever.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

// IdentityFile is the persisted shape on disk. Bump Version when the
// schema changes (any breaking format change requires re-registering
// the identity on-chain because the state derivation must stay reproducible).
type IdentityFile struct {
	Version   int            `json:"version"`
	DID       string         `json:"did"`
	BabyJub   BabyJubKey     `json:"babyjub"`
	State     string         `json:"state"`
	CreatedAt time.Time      `json:"created_at"`
	Notes     string         `json:"notes,omitempty"`
}

// BabyJubKey holds the wallet's BabyJubJub signing key. The private key
// is the raw 32-byte seed (the iden3 convention); the public key is the
// (X, Y) pair on the BabyJubJub curve, serialised as decimal strings of
// the underlying big.Int for round-tripability.
type BabyJubKey struct {
	PrivateKey string   `json:"private_key"` // hex(32 bytes)
	PublicKey  []string `json:"public_key"`  // [X.String(), Y.String()]
}

const identityFileVersion = 1

// identityInit creates a fresh BabyJubJub keypair, derives the iden3
// Auth claim, builds the genesis state from a single-leaf claims tree,
// computes the DID, and persists everything to outPath at mode 0600.
func identityInit(outPath string) error {
	// 1. Generate a random 32-byte BabyJubJub private key seed.
	var pkRaw babyjub.PrivateKey
	if _, err := rand.Read(pkRaw[:]); err != nil {
		return fmt.Errorf("read random bytes: %w", err)
	}

	pub := pkRaw.Public()

	// 2. Build the iden3 Auth claim. The Auth claim binds the public key
	// to the identity: it lives in the claims tree, and verifying a
	// signature against the public key is equivalent to proving the
	// signer controls this identity.
	authSchemaHash, err := core.NewSchemaHashFromHex("ca938857241db9451ea329256b9c06e5")
	if err != nil {
		return fmt.Errorf("auth schema hash: %w", err)
	}
	authClaim, err := core.NewClaim(
		authSchemaHash,
		core.WithIndexDataInts(pub.X, pub.Y),
		core.WithRevocationNonce(0),
	)
	if err != nil {
		return fmt.Errorf("build auth claim: %w", err)
	}

	// 3. Build the three identity trees (claims, revocations, roots).
	// For a fresh identity the claims tree has one entry (the Auth claim);
	// revocations and roots trees are empty. The state is the Poseidon
	// hash of the three roots.
	ctx := emptyContext()
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		return fmt.Errorf("claims tree: %w", err)
	}
	hi, hv, err := authClaim.HiHv()
	if err != nil {
		return fmt.Errorf("auth claim hi/hv: %w", err)
	}
	if err := claimsTree.Add(ctx, hi, hv); err != nil {
		return fmt.Errorf("add auth claim to claims tree: %w", err)
	}

	revTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		return fmt.Errorf("revocation tree: %w", err)
	}
	rootsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		return fmt.Errorf("roots tree: %w", err)
	}

	state, err := poseidon.Hash([]*big.Int{
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		rootsTree.Root().BigInt(),
	})
	if err != nil {
		return fmt.Errorf("compute genesis state: %w", err)
	}

	// 4. Derive the DID from the genesis state + the Privado main blockchain.
	// `privado:main` is the network the verifier resolver in
	// internal/auth/privado.go is wired to. If you target a different
	// resolver (e.g. Privado test, or a different Blockchain entirely),
	// update the BuildDIDType call to match — otherwise the proxy will
	// fail to resolve the identity's state on-chain.
	didType, err := core.BuildDIDType(core.DIDMethodIden3, core.Privado, core.Main)
	if err != nil {
		return fmt.Errorf("build DID type: %w", err)
	}
	did, err := core.NewDIDFromIdenState(didType, state)
	if err != nil {
		return fmt.Errorf("derive DID from state: %w", err)
	}

	// 5. Persist. Mode 0600 — operator-only read access. The file
	// contains the private key.
	// state.Bytes() is variable length (leading zeros stripped); pad to a
	// fixed 32-byte big-endian representation so the on-disk shape is
	// uniform — easier to diff between identities + easier to validate
	// on load.
	stateFixed := make([]byte, 32)
	state.FillBytes(stateFixed)

	idf := IdentityFile{
		Version:   identityFileVersion,
		DID:       did.String(),
		BabyJub:   BabyJubKey{
			PrivateKey: hex.EncodeToString(pkRaw[:]),
			PublicKey:  []string{pub.X.String(), pub.Y.String()},
		},
		State:     hex.EncodeToString(stateFixed),
		CreatedAt: time.Now().UTC(),
		Notes:     "Generated by wallet-emulator. Register the (DID, state) pair on the Privado state contract before using this identity for auth. See tools/wallet-emulator/README.md.",
	}
	body, err := json.MarshalIndent(idf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(outPath, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	fmt.Printf("Created identity:\n")
	fmt.Printf("  DID:   %s\n", idf.DID)
	fmt.Printf("  State: 0x%s\n", idf.State)
	fmt.Printf("  File:  %s (mode 0600)\n", outPath)
	fmt.Println()
	fmt.Println("NEXT: register the (DID, state) pair on the Privado state contract.")
	fmt.Println("      Until that's done the proxy verifier will reject every JWZ this identity produces.")
	fmt.Println("      See tools/wallet-emulator/README.md → 'On-chain registration'.")
	return nil
}

// identityShow prints the DID and state of an existing identity file
// without exposing the private key. Useful for sanity checks before an
// auth run or for re-registering the state after a key rotation.
func identityShow(path string) error {
	idf, err := loadIdentity(path)
	if err != nil {
		return err
	}
	fmt.Printf("DID:        %s\n", idf.DID)
	fmt.Printf("State:      0x%s\n", idf.State)
	fmt.Printf("Created at: %s\n", idf.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Schema ver: %d\n", idf.Version)
	if idf.Notes != "" {
		fmt.Printf("Notes:      %s\n", idf.Notes)
	}
	return nil
}

// loadIdentity reads and validates an identity file. Returns a sanitized
// IdentityFile struct ready for use by the auth flow.
func loadIdentity(path string) (*IdentityFile, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var idf IdentityFile
	if err := json.Unmarshal(body, &idf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if idf.Version != identityFileVersion {
		return nil, fmt.Errorf("unsupported identity-file version %d (this binary expects %d); regenerate with `identity init`", idf.Version, identityFileVersion)
	}
	if idf.DID == "" || idf.State == "" || idf.BabyJub.PrivateKey == "" {
		return nil, fmt.Errorf("identity file %s is missing required fields (did / state / babyjub.private_key)", path)
	}
	if len(idf.BabyJub.PublicKey) != 2 {
		return nil, fmt.Errorf("identity file %s: babyjub.public_key must be a [X, Y] pair", path)
	}
	return &idf, nil
}
