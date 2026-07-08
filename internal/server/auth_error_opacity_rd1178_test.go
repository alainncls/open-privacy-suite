package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

// RD-1178 #5 — the unauthenticated JWZ callback must return an opaque error.
//
// Before the fix, POST /api/v1/auth/callback returned
// `{"error":"JWZ verification failed: <raw verifier error>"}` to an anonymous
// caller. The raw error names the server verifier DID and circuit / issuer /
// schema internals, which aid proof forgery and config enumeration. The fix
// returns a fixed "authentication failed" and logs the detail via slog.
//
// This drives verifyAndIssueTokens directly (no DB): the JWZ-failure branch
// returns before any persistence, tryMockLogin is a no-op in the default build,
// and recordAuthAttempt is nil-safe when metrics are unset.
func TestVerifyAndIssueTokens_JWZFailure_OpaqueError_RD1178(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Secrets the raw error would leak — none of these may reach the client.
	const (
		leakVerifierDID = "did:privado:verifier-abc123"
		leakCircuit     = "credentialAtomicQueryMTPV2"
		leakIssuer      = "did:privado:issuer-xyz789"
	)
	rawErr := errors.New("JWZ proof invalid: circuit " + leakCircuit +
		" issuer " + leakIssuer + " for verifier " + leakVerifierDID + " schema mismatch")

	s := &Server{
		config: &config.Config{VerifierID: leakVerifierDID},
		privadoVerifier: &mockPrivadoVerifier{
			verifyWithProofDataFunc: func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error) {
				return nil, rawErr
			},
		},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/callback", nil)

	resp, err := s.verifyAndIssueTokens(c, "some.jwz.token", &protocol.AuthorizationRequestMessage{}, "session-123")
	if err == nil || resp != nil {
		t.Fatalf("expected failure (nil resp, non-nil err) on JWZ verification error, got resp=%v err=%v", resp, err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "authentication failed") {
		t.Errorf("expected opaque \"authentication failed\" message, got body: %s", body)
	}
	for _, leak := range []string{leakVerifierDID, leakCircuit, leakIssuer, "schema", "circuit", "JWZ"} {
		if strings.Contains(body, leak) {
			t.Errorf("RD-1178 regression: response body leaks internal verifier detail %q\nbody: %s", leak, body)
		}
	}
}
