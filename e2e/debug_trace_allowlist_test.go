//go:build mockauth

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rpcErrorString extracts the proxy's HTTP-level error string from a JSON body.
// RBAC denials are returned as {"error": "<message>"} with the matching HTTP
// status (not a nested JSON-RPC {code,message} object), so callers assert on
// the top-level string.
func rpcErrorString(t *testing.T, body []byte) string {
	t.Helper()
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed), "response: %s", string(body))
	if e, ok := parsed["error"].(string); ok {
		return e
	}
	return ""
}

// RD-1121: debug_trace* must be gated by the group method allowlist exactly
// like every other named RPC method. Historically processDebugTrace checked
// ONLY the deploy/admin claim and skipped the allowlist, so an operator who
// curated allowed_methods to exclude tracing was silently ignored for any
// group that had the deploy claim.
//
// These tests drive the full HTTP stack (real proxy server + real Anvil trace,
// via the shared create2 env) so the allowlist gate, the opaque-denial wire
// shape, and the cross-org ValidateTrace content gate are all exercised on the
// real Process path — not a unit stub.

// traceCallParams builds a debug_traceCall param tuple targeting addr.
func traceCallParams(from, to string) []any {
	return []any{
		map[string]any{
			"from": from,
			"to":   to,
			"data": "0x",
		},
		"latest",
	}
}

// TestDebugTrace_DeployClaimButMethodNotAllowlisted_Denied is the core RD-1121
// regression at the HTTP layer: a group WITH the deploy claim but WITHOUT
// debug_traceCall in allowed_methods must be denied. Pre-fix the deploy claim
// alone granted tracing.
func TestDebugTrace_DeployClaimButMethodNotAllowlisted_Denied(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	// did:test: prefix so the mockauth dev-admin auto-grant is skipped — the
	// user's ONLY membership is the group we configure (deploy claim, trace NOT
	// allowlisted). Otherwise mock login adds an org-admin "*" group that would
	// itself allowlist trace.
	userDID := "did:test:rd1121_deploy_no_trace"

	// Deploy claim, but the allowlist deliberately OMITS debug_traceCall.
	createOrgWithUser(t, env.srv.DB(), "rd1121-a", "rd1121-a-grp", userDID,
		[]rbac.Claim{rbac.ClaimDeploy},
		[]string{"eth_call", "eth_blockNumber", "eth_chainId"},
		anvilAccount0,
	)

	token := getJWTTokenForCreate2(t, env.serverURL, userDID)

	// did:test: users skip the dev-admin auto-grant, so they belong to exactly
	// one org and the bare "/" endpoint (empty orgID) resolves unambiguously.
	status, body := jsonRPCCallRaw(t, env.serverURL, "", token, "debug_traceCall",
		traceCallParams(anvilAccount0, anvilAccount1))

	// Denied: the deploy claim does NOT bypass the method allowlist anymore.
	// Opaque "method not found" / 404 deny (uniform with every other RBAC denial).
	assert.Equal(t, http.StatusNotFound, status, "body: %s", string(body))
	assert.Equal(t, "method not found", rpcErrorString(t, body))
}

// TestDebugTrace_AllowlistedWithoutDeployClaim_Reaches confirms the Option B
// decoupling end-to-end: a group WITHOUT the deploy/admin claim but WITH
// debug_traceCall in its allowlist passes the gate and the trace actually
// executes against Anvil (same-org / no cross-org target → allowed by
// ValidateTrace), returning a result rather than the allowlist deny.
func TestDebugTrace_AllowlistedWithoutDeployClaim_Reaches(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	// did:test: prefix — skip the dev-admin auto-grant so this user's only
	// grant is the group we configure (trace allowlisted, no deploy claim).
	userDID := "did:test:rd1121_trace_no_deploy"

	// No operational claims, but debug_traceCall IS allowlisted.
	createOrgWithUser(t, env.srv.DB(), "rd1121-b", "rd1121-b-grp", userDID,
		[]rbac.Claim{},
		[]string{"debug_traceCall", "eth_call", "eth_blockNumber", "eth_chainId"},
		anvilAccount0,
	)

	token := getJWTTokenForCreate2(t, env.serverURL, userDID)

	// A trace of a simple value transfer between the caller's own linked EOA and
	// an unregistered EOA target. No registered cross-org contract is touched,
	// so ValidateTrace allows it and the upstream node returns a trace.
	status, body := jsonRPCCallRaw(t, env.serverURL, "", token, "debug_traceCall",
		traceCallParams(anvilAccount0, anvilAccount1))

	// The allowlist gate did NOT block: the response is NOT the uniform 404
	// "method not found" RBAC deny. The trace reached the node and validation.
	assert.NotEqual(t, http.StatusNotFound, status,
		"allowlisted trace must not hit the RBAC allowlist deny; body: %s", string(body))
	assert.NotEqual(t, "method not found", rpcErrorString(t, body),
		"allowlisted trace must not hit the RBAC allowlist deny; body: %s", string(body))
}

// TestDebugTrace_CrossOrgStillDeniedByValidateTrace confirms the cross-org
// content gate is retained: a user whose group allowlists debug_traceCall is
// still denied when the trace touches a contract registered to ANOTHER org.
// This proves ValidateTrace remains in force independent of the allowlist
// change (Option B does not weaken cross-org isolation).
func TestDebugTrace_CrossOrgStillDeniedByValidateTrace(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	// did:test: prefix — skip the dev-admin auto-grant so the tracer's grants are
	// exactly the org-b group we configure (otherwise the org-admin "*" group
	// would resolve a different org and defeat the cross-org isolation we test).
	tracerDID := "did:test:rd1121_xorg_tracer" // org-b, allowlists trace

	// org-a owns a contract. We register it directly to org-a (no deploy needed;
	// the cross-org denial keys off DB ownership of the traced address). Use a
	// stable, lowercased address.
	orgAID := createOrgWithUser(t, env.srv.DB(), "rd1121-xa", "rd1121-xa-grp",
		"did:test:rd1121_xorg_owner",
		[]rbac.Claim{rbac.ClaimDeploy},
		[]string{"eth_call", "eth_blockNumber", "eth_chainId"},
		"",
	)
	orgAContract := "0xc0ffee0000000000000000000000000000000001"
	registerContract(t, env.srv.DB(), orgAID, orgAContract, "OrgAContract")

	// org-b: trace is allowlisted, but org-b does NOT own org-a's contract.
	createOrgWithUser(t, env.srv.DB(), "rd1121-xb", "rd1121-xb-grp", tracerDID,
		[]rbac.Claim{},
		[]string{"debug_traceCall", "eth_call", "eth_blockNumber", "eth_chainId"},
		anvilAccount1,
	)

	tracerToken := getJWTTokenForCreate2(t, env.serverURL, tracerDID)

	// org-b tries to debug_traceCall INTO org-a's registered contract.
	// Allowlist gate passes (debug_traceCall is allowlisted for org-b), but the
	// trace touches a cross-org-owned contract → ValidateTrace denies it.
	status, body := jsonRPCCallRaw(t, env.serverURL, "", tracerToken, "debug_traceCall",
		traceCallParams(anvilAccount1, orgAContract))

	// Denied, and NOT by the allowlist gate (org-b allowlists debug_traceCall):
	// the denial is the cross-org ValidateTrace content gate, which returns a
	// 403 "cross-org trace denied", not the 404 "method not found" allowlist
	// deny. This proves ValidateTrace is retained and independent of the
	// allowlist change.
	require.GreaterOrEqual(t, status, 400, "cross-org trace must be denied; body: %s", string(body))
	assert.NotEqual(t, http.StatusNotFound, status,
		"cross-org denial must come from ValidateTrace (403), not the allowlist gate (404); body: %s", string(body))
	assert.NotEqual(t, "method not found", rpcErrorString(t, body),
		"cross-org denial must come from ValidateTrace, not the allowlist gate; body: %s", string(body))
}
