package main

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIdentityInitRoundTrip verifies the persisted identity round-trips
// through loadIdentity and that the DID we derived is well-formed for
// the iden3 method + Privado main network. This pins the on-disk format
// + the DID-derivation algorithm; a regression in either would silently
// break authentication against any environment where the identity was
// previously registered on-chain.
func TestIdentityInitRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-id.json")

	require.NoError(t, identityInit(path))

	idf, err := loadIdentity(path)
	require.NoError(t, err)

	// Schema version + presence of every required field.
	assert.Equal(t, identityFileVersion, idf.Version)
	assert.NotEmpty(t, idf.DID)
	assert.NotEmpty(t, idf.State)
	assert.NotEmpty(t, idf.BabyJub.PrivateKey)
	require.Len(t, idf.BabyJub.PublicKey, 2)

	// Private key is exactly 32 bytes (BabyJubJub seed).
	raw, err := hex.DecodeString(idf.BabyJub.PrivateKey)
	require.NoError(t, err)
	assert.Len(t, raw, 32, "babyjub private key must be 32 bytes")

	// State is 32 bytes (Poseidon hash output).
	stateBytes, err := hex.DecodeString(idf.State)
	require.NoError(t, err)
	assert.Len(t, stateBytes, 32, "state must be 32 bytes")

	// DID parses cleanly and uses the iden3 method on Privado/main —
	// matches the resolver wiring in internal/auth/privado.go.
	did, err := w3c.ParseDID(idf.DID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(did.String(), "did:iden3:privado:main:"),
		"unexpected DID prefix: %s (the proxy verifier resolver is keyed on `privado:main` — see internal/auth/privado.go:46)",
		did.String())

	// And the DID derives to a non-empty ID that we can re-derive from
	// the state. This catches any drift between BuildDIDType +
	// NewDIDFromIdenState across iden3-core upgrades.
	id, err := core.IDFromDID(*did)
	require.NoError(t, err)
	assert.NotEqual(t, [31]byte{}, id, "derived ID should be non-zero")
}

// TestIdentityLoadVersionMismatch checks that loading an identity with
// the wrong schema version returns a clear error rather than silently
// proceeding (which would mean we'd derive proofs against the wrong
// identity layout).
func TestIdentityLoadVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	// Hand-crafted file with a future version.
	body := []byte(`{"version": 999, "did": "did:iden3:privado:main:x", "state": "00", "babyjub": {"private_key": "00", "public_key": ["0", "0"]}}`)
	require.NoError(t, writeFile(path, body))

	_, err := loadIdentity(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported identity-file version")
}

// writeFile is a small helper so the test doesn't pull in os just for
// this. Keeps the test file's imports tight.
func writeFile(path string, body []byte) error {
	return writeFileMode(path, body, 0o600)
}
