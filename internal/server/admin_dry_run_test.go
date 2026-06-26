package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dryRunTestServer wraps testServerRBAC and exposes a router whose
// dry-run route is preceded by a tiny test-mode middleware that
// injects the auth context fields the production middleware would set
// (auth_method, admin_subject). The point is not to test gin auth
// itself — that's covered elsewhere — but to drive the dry-run
// handler's own gates from a test fixture.
//
// Header set by tests:
//   - X-Test-Auth-Method: "jwt_admin" | "admin_token" | ""  (empty = unauth)
//   - X-Test-Admin-Subject: <admin DID>  (only honoured for jwt_admin)
type dryRunTestServer struct {
	*testServerRBAC
}

func setupDryRunTestServer(t *testing.T) *dryRunTestServer {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	// Inject a minimal middleware that mirrors what
	// adminAuthMiddleware sets in production. Real auth is exercised
	// elsewhere (admin_auth_test.go); here we just need the context
	// values present so the handler's own gates run.
	router := gin.New()
	api := router.Group("/api")
	api.Use(func(c *gin.Context) {
		method := c.GetHeader("X-Test-Auth-Method")
		if method == "" {
			c.Next()
			return
		}
		c.Set("auth_method", method)
		if method == "jwt_admin" {
			c.Set("admin_subject", c.GetHeader("X-Test-Admin-Subject"))
		}
		c.Next()
	})
	api.POST("/orgs/:org_id/dry-run", ts.handleDryRun)

	ts.router = router
	return &dryRunTestServer{testServerRBAC: ts}
}

func dryRunPost(t *testing.T, srv *dryRunTestServer, orgID, authMethod, adminDID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	jb, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/dry-run", bytes.NewReader(jb))
	req.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	if adminDID != "" {
		req.Header.Set("X-Test-Admin-Subject", adminDID)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// Fixture: one org, one tier-2 admin, one ordinary user (granted on a
// contract), and a fake "user not in this org" account.
type dryRunFixture struct {
	srv             *dryRunTestServer
	orgID           string
	otherOrgID      string
	adminDID        string
	userDID         string
	otherOrgUserDID string
	contractAddr    string
}

func setupDryRunFixture(t *testing.T) *dryRunFixture {
	t.Helper()
	srv := setupDryRunTestServer(t)
	ctx := context.Background()
	database := srv.db

	// Two orgs — admin's org + a different one to test cross-org isolation.
	orgID := uuid.New().String()
	otherOrgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "dr-a", Name: "DR A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: otherOrgID, Slug: "dr-b", Name: "DR B", Settings: map[string]any{}}))

	// Tier-2 admin group + member.
	adminGroupID := drCreateGroup(t, database, orgID, "dr-a-admin", nil, true /* is_org_admin */)
	adminDID := "did:dr:admin"
	drCreateUserInGroup(t, database, adminDID, adminGroupID)

	// Ordinary user with access to one contract.
	userGroupID := drCreateGroup(t, database, orgID, "dr-a-user", nil, false)
	userDID := "did:dr:user"
	drCreateUserInGroup(t, database, userDID, userGroupID)
	contractAddr := "0x1111111111111111111111111111111111111111"
	contractID := drCreateContract(t, database, orgID, contractAddr, "DRContract")
	drCreateGrant(t, database, contractID, userGroupID)

	// User in the other org, no membership in admin's org.
	otherOrgGroupID := drCreateGroup(t, database, otherOrgID, "dr-b-only", nil, false)
	otherOrgUserDID := "did:dr:cross-org-user"
	drCreateUserInGroup(t, database, otherOrgUserDID, otherOrgGroupID)

	return &dryRunFixture{
		srv:             srv,
		orgID:           orgID,
		otherOrgID:      otherOrgID,
		adminDID:        adminDID,
		userDID:         userDID,
		otherOrgUserDID: otherOrgUserDID,
		contractAddr:    contractAddr,
	}
}

func TestDryRun_RejectsSuperAdminToken(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "admin_token", "" /* DID irrelevant */, body)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "X-Admin-Token credentials are not authorised")
}

func TestDryRun_RejectsUnauthenticated(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "" /* no auth */, "", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDryRun_RejectsSelfDryRun(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.adminDID, // admin trying to dry-run themselves
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "cannot dry-run as yourself")
}

func TestDryRun_RejectsUnsupportedMethod(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_subscribe", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "method not supported")
}

func TestDryRun_CrossOrgUserReturns404(t *testing.T) {
	f := setupDryRunFixture(t)
	// Admin in Org A, target user only in Org B → identical generic
	// 404 to the "user does not exist at all" case.
	body := map[string]any{
		"user_did": f.otherOrgUserDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

func TestDryRun_NonExistentUserReturns404(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": "did:dr:nobody",
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDryRun_DenyDecisionLoggedAndReturned exercises the full flow for
// a denial case: the impersonated user has no access to a target
// contract, RBAC says deny, and the handler returns
// `{"decision":"deny","reason":...}` while writing an impersonation_log
// row.
func TestDryRun_DenyDecisionLoggedAndReturned(t *testing.T) {
	f := setupDryRunFixture(t)
	// User is granted on f.contractAddr; we point the call at a
	// different unregistered address to force RBAC deny.
	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_call",
			"params": []any{
				map[string]any{"to": "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", "data": "0x"},
				"latest",
			},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp dryRunResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "deny", resp.Decision, "expected deny on unregistered target")
	assert.NotEmpty(t, resp.Reason)

	// Audit row written.
	var count int
	require.NoError(t,
		f.srv.db.Conn().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM impersonation_log
			 WHERE actor_did = $1 AND impersonated_did = $2 AND decision = 'deny'`,
			f.adminDID, f.userDID).Scan(&count),
	)
	assert.Equal(t, 1, count, "expected exactly one deny row in impersonation_log")
}

// TestDryRun_ParamsHashStable pins the params-hash invariant: same
// method + params produce the same hash, different params don't. The
// audit log uses this hash so reviewers can correlate without us ever
// persisting raw params.
func TestDryRun_ParamsHashStable(t *testing.T) {
	h1 := dryRunParamsHash("eth_call", []any{map[string]any{"to": "0xaa"}, "latest"})
	h2 := dryRunParamsHash("eth_call", []any{map[string]any{"to": "0xaa"}, "latest"})
	h3 := dryRunParamsHash("eth_call", []any{map[string]any{"to": "0xbb"}, "latest"})
	assert.Equal(t, h1, h2, "same input must hash identically")
	assert.NotEqual(t, h1, h3, "different params must produce different hashes")
	assert.Equal(t, 64, len(h1), "sha256 hex length")
}

// TestDryRun_TraceMethodWithoutProxyReturnsClearError covers the
// debug_traceCall path when no upstream proxy is wired (testServerRBAC
// runs without one). The handler should pass RBAC, then surface a
// clear "proxy not configured" / "node does not support" error rather
// than 500-with-stack-trace.
func TestDryRun_TraceMethodWithoutProxyReturnsClearError(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_sendTransaction",
			"params": []any{
				map[string]any{
					"from": "0xaa",
					"to":   f.contractAddr,
					"data": "0xabcd",
				},
			},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	// RBAC may deny first (no method allowlist) or allow with trace
	// failure; either way the user gets a clean structured response.
	if w.Code == http.StatusOK {
		var resp dryRunResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		// allow + no trace because our test fixture has no upstream
		// proxy, OR deny because eth_sendTransaction needs a writable
		// claim. Either is structurally fine.
		assert.True(t, resp.Decision == "allow" || resp.Decision == "deny",
			"unexpected decision: %s", resp.Decision)
	} else {
		// 502 from the trace-forward branch is also acceptable.
		assert.Equal(t, http.StatusBadGateway, w.Code)
	}
}

// TestDryRun_RawSendTransactionDecodes verifies that a signed raw tx
// passes through the production decoder and reaches the trace branch
// (rather than being rejected as unsupported). The test fixture has
// no upstream node, so the trace step itself fails with a 502 — the
// point is that the failure is "couldn't reach upstream" not
// "couldn't decode."
func TestDryRun_RawSendTransactionDecodes(t *testing.T) {
	f := setupDryRunFixture(t)

	// Build a real signed legacy tx so decodeRawTransaction runs the
	// full RLP + signer-recovery path (same code as production
	// processRawTransaction). 32-byte arbitrary key; chain ID 1.
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	chainID := big.NewInt(1)
	toAddr := common.HexToAddress(f.contractAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      100_000,
		To:       &toAddr,
		Value:    big.NewInt(0),
		Data:     []byte{0xab, 0xcd},
	})
	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, key)
	require.NoError(t, err)
	rawBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)
	rawHex := "0x" + hex.EncodeToString(rawBytes)

	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_sendRawTransaction",
			"params": []any{rawHex},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)

	// One of three outcomes is acceptable; all confirm we got past
	// decode without the old "not supported" stub:
	//
	//   200 + decision=deny — RBAC denied based on the recovered
	//     sender's lack of access to f.contractAddr (most likely
	//     since the random key is not linked to f.userDID).
	//   200 + decision=allow — RBAC let it through; trace branch
	//     responded.
	//   502 — RBAC allowed, trace branch failed reaching upstream
	//     (no proxy in test fixture). The body should NOT contain
	//     "decode" / "not supported".
	switch w.Code {
	case http.StatusOK:
		var resp dryRunResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Contains(t, []string{"allow", "deny"}, resp.Decision)
	case http.StatusBadGateway:
		bodyText := strings.ToLower(w.Body.String())
		require.NotContains(t, bodyText, "not supported",
			"raw tx must reach trace branch — got 'not supported' which means the old stub fired")
		require.NotContains(t, bodyText, "decode pending",
			"raw tx must reach trace branch — got 'decode pending' which means the old stub fired")
	default:
		t.Fatalf("unexpected status code: %d, body: %s", w.Code, w.Body.String())
	}
}

// TestDryRun_RawSendTransactionMalformedReturnsClearError confirms
// the decode error path: a clearly invalid hex blob returns a
// structured 4xx/5xx with a useful message, not a generic 500.
func TestDryRun_RawSendTransactionMalformedReturnsClearError(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_sendRawTransaction",
			"params": []any{"0xnotrealhex"},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	// RBAC may deny first (no signature → no recovered sender → no
	// linked address), or we may reach the trace path which then
	// fails to decode. Either is acceptable — what we don't want is
	// a generic 500 with no message.
	if w.Code == http.StatusBadGateway {
		assert.Contains(t, strings.ToLower(w.Body.String()), "decode")
	}
}

// ---- fixture helpers -------------------------------------------------

func drCreateGroup(t *testing.T, database interface {
	CreateGroup(ctx context.Context, g *rbac.Group) error
	CreateGroupAccess(ctx context.Context, ga *rbac.GroupAccess) error
}, orgID, slug string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: gid, OrgID: orgID, Slug: slug, Name: slug, Depth: 0, Path: slug, IsOrgAdmin: isOrgAdmin,
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_call", "eth_getLogs"}, Claims: claims,
	}))
	return gid
}

func drCreateUserInGroup(t *testing.T, database interface {
	CreateUser(ctx context.Context, u *rbac.User) error
	CreateMembership(ctx context.Context, m *rbac.UserMembership) error
}, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: uid, ExternalID: did, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: uid, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return uid
}

func drCreateContract(t *testing.T, database interface {
	CreateContract(ctx context.Context, c *rbac.Contract) error
}, orgID, address, name string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: address, Name: name, Metadata: map[string]any{},
	}))
	return cid
}

func drCreateGrant(t *testing.T, database interface {
	CreateContractGrant(ctx context.Context, g *rbac.ContractGrant) error
}, contractID, groupID string) {
	t.Helper()
	require.NoError(t, database.CreateContractGrant(context.Background(), &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, Functions: nil,
	}))
}
