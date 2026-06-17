package server

import (
	"net/http"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DID-validation tests for the by-did onboarding endpoint (RD-1098).
//
// Before the fix the `did` field was accepted verbatim and a not-yet-seen
// value was provisioned into a `users` row. A typo'd DID, the wallet *app* DID
// (vs the user's *account* DID), or arbitrary garbage all returned 201 and
// created a dead membership row that no real login would ever match.

// A real, checksum-valid Privado-main DID (decoded with go-iden3-core/v2:
// method=iden3, blockchain=privado, network=main, checksum OK).
const validIden3DID = "did:iden3:privado:main:2SiJJTxakwEi9fUNDtut3Ezxc1UA1AZLTAyekfgQrW"

func TestValidateOnboardDID(t *testing.T) {
	cases := []struct {
		name    string
		did     string
		wantErr bool
	}{
		{"valid iden3 privado main", validIden3DID, false},
		// Last base58 char flipped W->X: parses as a DID but fails the iden3
		// identifier checksum.
		{"iden3 bad checksum", "did:iden3:privado:main:2SiJJTxakwEi9fUNDtut3Ezxc1UA1AZLTAyekfgQrX", true},
		// Well-formed iden3 method but a short/garbage identifier.
		{"iden3 truncated identifier", "did:iden3:privado:main:2SaubQ6Vu4Xdq8eDDfBcZj", true},
		{"empty", "", true},
		{"plain string", "not-a-did", true},
		{"ethereum address", "0x1234567890abcdef1234567890abcdef12345678", true},
		{"email", "user@example.com", true},
		// Azure AD subjects use the `azuread:` scheme, not a W3C DID. They are
		// provisioned via the Azure login flow, never this endpoint.
		{"azuread subject", "azuread:abc-123-def", true},
		// Non-iden3 DID methods are accepted on structure alone — no iden3
		// checksum exists to verify, and they don't reach this endpoint in
		// production. (did:test is used by the sibling onboard tests.)
		{"non-iden3 did:test", "did:test:bob-1234", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOnboardDID(tc.did)
			if tc.wantErr {
				assert.Error(t, err, "expected %q to be rejected", tc.did)
			} else {
				assert.NoError(t, err, "expected %q to be accepted", tc.did)
			}
		})
	}
}

func TestOnboardByDID_InvalidDID_400_NoDeadRow(t *testing.T) {
	// An invalid DID must be rejected with an opaque 400 and must NOT create a
	// users row (fail-closed — no silent dead membership).
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-inv", Name: "Team", Path: "team-inv"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	bad := []struct{ name, did string }{
		{"bad_checksum", "did:iden3:privado:main:2SiJJTxakwEi9fUNDtut3Ezxc1UA1AZLTAyekfgQrX"},
		{"garbage", "the-app-did-i-copied-by-mistake"},
		{"eth_address", "0x1234567890abcdef1234567890abcdef12345678"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: tc.did, GroupID: normalGroup.ID})
			require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), "invalid did")
			// Opaque: no raw parser internals leaked to the client.
			assert.NotContains(t, w.Body.String(), "checksum")
			assert.NotContains(t, w.Body.String(), "w3c")

			u, err := srv.db.GetUserByExternalID(ctx, tc.did)
			require.NoError(t, err)
			assert.Nil(t, u, "invalid DID must not create a users row")
		})
	}
}

func TestOnboardByDID_ValidIden3DID_201(t *testing.T) {
	// A real checksum-valid Privado DID onboards normally.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-valid", Name: "Team", Path: "team-valid"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: validIden3DID, GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "valid iden3 DID must onboard; body: %s", w.Body.String())

	u, err := srv.db.GetUserByExternalID(ctx, validIden3DID)
	require.NoError(t, err)
	require.NotNil(t, u, "valid DID should have created the users row")
}

func TestOnboardByDID_WhitespaceTrimmed(t *testing.T) {
	// A copy-pasted DID with surrounding whitespace must be trimmed and stored
	// in canonical form, so the row matches the DID the user later presents at
	// login (the verified ZK-proof `From`, which carries no whitespace).
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-trim", Name: "Team", Path: "team-trim"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: "  " + validIden3DID + "\n", GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "padded DID should be trimmed and accepted; body: %s", w.Body.String())

	u, err := srv.db.GetUserByExternalID(ctx, validIden3DID)
	require.NoError(t, err)
	require.NotNil(t, u, "DID must be stored trimmed so it matches the login DID")
}
