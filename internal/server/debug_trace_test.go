package server

import (
	"context"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopRateLimiter always allows requests.
type noopRateLimiter struct{}

func (n *noopRateLimiter) CheckAndIncrement(string, *int, *int) (bool, string) {
	return true, ""
}
func (n *noopRateLimiter) Stop() {}

// setupProcessorWithoutTracing creates a JSONRPCProcessor with no runtime tracer.
// This simulates a proxy deployment where tracing is disabled.
func setupProcessorWithoutTracing(t *testing.T) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	proc := NewJSONRPCProcessor(
		ts.rbacAccessCtrl,
		&noopRateLimiter{},
		nil, // no proxy needed for negative path tests
		ts.db,
		NewCircuitBreaker(),
		NewConcurrencyLimiter(50),
		"",
	)
	return proc, ts
}

// setupProcessorWithTracing creates a JSONRPCProcessor with an enabled runtime tracer.
// The tracer points to an unreachable URL, which is fine because the tests exercise
// paths that fail before reaching the actual trace call.
func setupProcessorWithTracing(t *testing.T) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{
		NodeURL: "http://127.0.0.1:1", // unreachable; tests don't reach the tracer
		Enabled: true,
	})
	t.Cleanup(rt.Stop)

	tv := rbac.NewTraceValidator(ts.db)

	proc := NewJSONRPCProcessorWithTracing(
		ts.rbacAccessCtrl,
		&noopRateLimiter{},
		nil, // no proxy needed
		ts.db,
		rt,
		tv,
		NewCircuitBreaker(),
		NewConcurrencyLimiter(50),
		"",
	)
	return proc, ts
}

// insertGroupRawSQL inserts a group using raw SQL to avoid dependence on migration 028
// (auto_created column). This allows the tests to run on branches where that migration
// has not yet been applied.
func insertGroupRawSQL(t *testing.T, ctx context.Context, database *db.DB, id, orgID, slug, name, path string) {
	t.Helper()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, depth, is_org_admin)
		 VALUES ($1, $2, $3, $4, $5, 0, false)`,
		id, orgID, slug, name, path,
	)
	require.NoError(t, err)
}

// createOrgGroupUserMembership creates an org, group, group access, user, and membership
// in one call. Returns the user's external ID. The group gets the specified claims.
func createOrgGroupUserMembership(t *testing.T, ctx context.Context, database *db.DB, claims []rbac.Claim) string {
	t.Helper()

	orgID := uuid.New().String()
	groupID := uuid.New().String()
	userID := uuid.New().String()
	externalID := "did:privado:test-" + uuid.New().String()

	err := database.CreateOrganization(ctx, &rbac.Organization{
		ID:   orgID,
		Slug: "test-org-" + orgID[:8],
		Name: "Test Org",
	})
	require.NoError(t, err)

	insertGroupRawSQL(t, ctx, database, groupID, orgID,
		"test-group-"+groupID[:8], "Test Group", "test-group-"+groupID[:8])

	err = database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		Claims:         claims,
		AllowedMethods: []string{},
	})
	require.NoError(t, err)

	err = database.CreateUser(ctx, &rbac.User{
		ID:         userID,
		ExternalID: externalID,
	})
	require.NoError(t, err)

	err = database.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: groupID,
		Source:  rbac.MembershipSourceAdmin,
	})
	require.NoError(t, err)

	return externalID
}

func TestDebugTrace_DeniedWhenTracingDisabled(t *testing.T) {
	proc, _ := setupProcessorWithoutTracing(t)
	ctx := context.Background()

	req := &ProcessRequest{
		UserID: "did:privado:some-user",
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error when tracing is disabled")
	assert.Equal(t, 403, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "not supported or enabled")
}

func TestDebugTrace_DeniedWithoutDeployClaim(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	// Create a user with read-only access (no deploy claim)
	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimRead})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error without deploy claim")
	assert.Equal(t, 403, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "deploy or admin claims")
}

func TestDebugTrace_DeniedForUnknownUser(t *testing.T) {
	proc, _ := setupProcessorWithTracing(t)
	ctx := context.Background()

	req := &ProcessRequest{
		UserID: "did:privado:nonexistent-user",
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error for unknown user")
	assert.Equal(t, 401, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "failed to get user")
}

func TestDebugTrace_DeployClaimReachesTracer(t *testing.T) {
	// A user with deploy claim passes the claim check but fails at the tracer
	// level because the tracer points to an unreachable node.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimDeploy})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xdeadbeef"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	// The error should be from the trace execution, not from a claim check.
	// This proves the claim check passed and we reached the tracer.
	assert.NotContains(t, result.Error.Message, "deploy or admin claims")
	assert.NotContains(t, result.Error.Message, "not supported or enabled")
}

func TestDebugTrace_AdminClaimAlsoAllowed(t *testing.T) {
	// Admin claim should also pass the deploy-or-admin check.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimAdmin})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xdeadbeef"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	// Should pass claim check and fail at tracer level
	assert.NotContains(t, result.Error.Message, "deploy or admin claims")
}

func TestDebugTrace_WriteOnlyClaimDenied(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimWrite})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xabc"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error)
	assert.Equal(t, 403, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "deploy or admin claims")
}

func TestDebugTrace_DebugTraceCallAlsoHandled(t *testing.T) {
	// debug_traceCall goes through the same code path.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimDeploy})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceCall",
		Params: []any{map[string]any{
			"from":  "0x1111111111111111111111111111111111111111",
			"to":    "0x2222222222222222222222222222222222222222",
			"data":  "0x",
			"value": "0x0",
		}},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	// Should pass claim check for debug_traceCall as well
	assert.NotContains(t, result.Error.Message, "deploy or admin claims")
}

func TestDebugTrace_MissingTxHashReturnsBadRequest(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimDeploy})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{}, // empty params
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error)
	assert.Equal(t, 400, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "missing transaction hash")
}

func TestDebugTrace_NoMembershipsDenied(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	// Create a user with no memberships at all
	userID := uuid.New().String()
	externalID := "did:privado:nomember-" + uuid.New().String()

	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{
		ID: userID, ExternalID: externalID,
	}))

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xabc"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error)
	// No memberships means no deploy claim
	assert.Equal(t, 403, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "deploy or admin claims")
}
