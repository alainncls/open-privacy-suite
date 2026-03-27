package governance_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/governance"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockApplier just records that it was called
type mockApplier struct {
	called bool
	err    error
}

func (m *mockApplier) ApplyGovernanceMutation(ctx context.Context, req *rbac.ApprovalRequest) error {
	m.called = true
	return m.err
}

// mockNotifier just records that it was called
type mockNotifier struct {
	newReqCount    int
	escalatedCount int
}

func (m *mockNotifier) NotifyNewRequest(ctx context.Context, req *rbac.ApprovalRequest) error {
	m.newReqCount++
	return nil
}

func (m *mockNotifier) NotifyEscalation(ctx context.Context, req *rbac.ApprovalRequest) error {
	m.escalatedCount++
	return nil
}

func setupTestDB(t *testing.T) *db.DB {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		require.NoError(t, db.EnsureTestDatabase(dbURL))
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)

	err = database.Migrate(context.Background())
	require.NoError(t, err)

	// Clean tables
	ctx := context.Background()
	conn := database.Conn()
	conn.ExecContext(ctx, "DELETE FROM approval_notifications")
	conn.ExecContext(ctx, "DELETE FROM approval_decisions")
	conn.ExecContext(ctx, "DELETE FROM approval_requests")
	conn.ExecContext(ctx, "DELETE FROM organizations")

	t.Cleanup(func() {
		database.Close()
	})

	return database
}

func createTestOrg(t *testing.T, database *db.DB) *rbac.Organization {
	org := &rbac.Organization{
		ID:        uuid.New().String(),
		Slug:      "test-gov-org-" + uuid.New().String()[:8],
		Name:      "Test Gov Org",
		Settings:  map[string]any{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, database.CreateOrganization(context.Background(), org))
	return org
}

func createTestUser(t *testing.T, database *db.DB, id string) {
	user := &rbac.User{
		ID:         id,
		ExternalID: "did:test:" + id[:8],
		KYC:        true,
		Metadata:   map[string]any{},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	require.NoError(t, database.CreateUser(context.Background(), user))
}

func TestEngine_ProcessDecision_HappyPath_Threshold1(t *testing.T) {
	database := setupTestDB(t)
	org := createTestOrg(t, database)
	ctx := context.Background()

	applier := &mockApplier{}
	notifier := &mockNotifier{}
	engine := governance.NewEngine(database, applier, notifier)

	requesterID := uuid.New().String()
	approverID := uuid.New().String()
	createTestUser(t, database, requesterID)
	createTestUser(t, database, approverID)

	// Create request
	payload := json.RawMessage(`{"foo":"bar"}`)
	req, err := engine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, payload, 1)
	require.NoError(t, err)
	assert.Equal(t, rbac.StatusPending, req.Status)

	req, err = engine.ProcessDecision(ctx, req.OrgID, req.ID, approverID, "approve", nil)
	require.NoError(t, err)

	assert.Equal(t, rbac.StatusApproved, req.Status)
	assert.True(t, applier.called, "applier should be invoked when threshold met")
	assert.NotNil(t, req.ResolvedAt)
}

func TestEngine_ProcessDecision_HappyPath_Threshold2(t *testing.T) {
	database := setupTestDB(t)
	org := createTestOrg(t, database)
	ctx := context.Background()

	applier := &mockApplier{}
	engine := governance.NewEngine(database, applier, &mockNotifier{})

	user1 := uuid.New().String()
	user2 := uuid.New().String()
	user3 := uuid.New().String()
	createTestUser(t, database, user1)
	createTestUser(t, database, user2)
	createTestUser(t, database, user3)

	req, err := engine.SubmitChange(ctx, org.ID, user1, "test_change", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	// 1st approval
	req1, err := engine.ProcessDecision(ctx, req.OrgID, req.ID, user2, "approve", nil)
	require.NoError(t, err)
	assert.Equal(t, rbac.StatusPending, req1.Status, "should still be pending after 1 approval")
	assert.False(t, applier.called)

	// 2nd approval
	reason := "LGTM"
	req2, err := engine.ProcessDecision(ctx, req.OrgID, req.ID, user3, "approve", &reason)
	require.NoError(t, err)
	assert.Equal(t, rbac.StatusApproved, req2.Status, "should be approved after 2 approvals")
	assert.True(t, applier.called)
}

func TestEngine_ProcessDecision_Reject(t *testing.T) {
	database := setupTestDB(t)
	org := createTestOrg(t, database)
	ctx := context.Background()

	applier := &mockApplier{}
	engine := governance.NewEngine(database, applier, &mockNotifier{})

	user1 := uuid.New().String()
	user2 := uuid.New().String()
	createTestUser(t, database, user1)
	createTestUser(t, database, user2)

	req, err := engine.SubmitChange(ctx, org.ID, user1, "test_change", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	// Rejection immediately fails the request even if threshold is 2
	reason := "Nope"
	req1, err := engine.ProcessDecision(ctx, req.OrgID, req.ID, user2, "reject", &reason)
	require.NoError(t, err)
	
	assert.Equal(t, rbac.StatusRejected, req1.Status)
	assert.False(t, applier.called)
}

func TestEngine_ProcessDecision_AlreadyResolved(t *testing.T) {
	database := setupTestDB(t)
	org := createTestOrg(t, database)
	ctx := context.Background()
	engine := governance.NewEngine(database, &mockApplier{}, &mockNotifier{})

	user1 := uuid.New().String()
	user2 := uuid.New().String()
	user3 := uuid.New().String()
	createTestUser(t, database, user1)
	createTestUser(t, database, user2)
	createTestUser(t, database, user3)

	req, err := engine.SubmitChange(ctx, org.ID, user1, "test_change", nil, nil, json.RawMessage(`{}`), 1)
	require.NoError(t, err)

	// 1st approval (resolves it)
	_, err = engine.ProcessDecision(ctx, req.OrgID, req.ID, user2, "approve", nil)
	require.NoError(t, err)

	// Try to approve again
	_, err = engine.ProcessDecision(ctx, req.OrgID, req.ID, user3, "approve", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no longer pending")
}

func TestEngine_DoubleVotingPrevention(t *testing.T) {
	database := setupTestDB(t)
	org := createTestOrg(t, database)
	ctx := context.Background()
	engine := governance.NewEngine(database, &mockApplier{}, &mockNotifier{})

	user1 := uuid.New().String()
	user2 := uuid.New().String()
	createTestUser(t, database, user1)
	createTestUser(t, database, user2)

	req, err := engine.SubmitChange(ctx, org.ID, user1, "test_change", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	// 1st approval
	_, err = engine.ProcessDecision(ctx, req.OrgID, req.ID, user2, "approve", nil)
	require.NoError(t, err)

	// 2nd approval by SAME user
	_, err = engine.ProcessDecision(ctx, req.OrgID, req.ID, user2, "approve", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already voted") // Assuming DB unique constraint catches it! Or we handle it.
}
