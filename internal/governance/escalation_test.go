package governance_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/governance"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEscalationWorker_EscalatesStaleRequests(t *testing.T) {
	database := setupTestDB(t)
	ctx := context.Background()

	// Create an org with governance enabled and a 1-hour escalation timeout.
	org := &rbac.Organization{
		ID:                               uuid.New().String(),
		Slug:                             "test-esc-org-" + uuid.New().String()[:8],
		Name:                             "Escalation Test Org",
		Settings:                         map[string]any{},
		GovernanceEnabled:                true,
		ApprovalThreshold:                2,
		GovernanceEscalationTimeoutHours: 1,
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	requesterID := uuid.New().String()
	createTestUser(t, database, requesterID)

	// Create a pending approval request with an old created_at timestamp (2 hours ago).
	notifier := &mockNotifier{}
	engine := governance.NewEngine(database, &mockApplier{}, notifier)

	req, err := engine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{"key":"value"}`), 2)
	require.NoError(t, err)
	assert.Equal(t, rbac.StatusPending, req.Status)

	// Manually backdate the created_at to 2 hours ago so it exceeds the 1-hour timeout.
	conn := database.Conn()
	_, err = conn.ExecContext(ctx, `UPDATE approval_requests SET created_at = $2 WHERE id = $1`,
		req.ID, time.Now().Add(-2*time.Hour))
	require.NoError(t, err)

	// Run the escalation worker with a very short interval. We don't use Start() here;
	// instead we call the exported method or create and immediately trigger.
	// Since escalateStaleRequests is unexported, we use the worker's run cycle.
	worker := governance.NewEscalationWorker(database, notifier, 100*time.Millisecond)
	worker.Start()

	// Wait for at least one tick to process.
	time.Sleep(300 * time.Millisecond)
	worker.Stop()

	// Verify notification was sent.
	assert.Equal(t, 1, notifier.escalatedCount, "escalation notification should be sent once")

	// Verify the request was marked as escalated in the database.
	updatedReq, err := database.GetApprovalRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedReq.EscalatedAt, "escalated_at should be set")
}

func TestEscalationWorker_SkipsAlreadyEscalated(t *testing.T) {
	database := setupTestDB(t)
	ctx := context.Background()

	org := &rbac.Organization{
		ID:                               uuid.New().String(),
		Slug:                             "test-esc-skip-" + uuid.New().String()[:8],
		Name:                             "Escalation Skip Test",
		Settings:                         map[string]any{},
		GovernanceEnabled:                true,
		ApprovalThreshold:                2,
		GovernanceEscalationTimeoutHours: 1,
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	requesterID := uuid.New().String()
	createTestUser(t, database, requesterID)

	notifier := &mockNotifier{}
	engine := governance.NewEngine(database, &mockApplier{}, notifier)

	req, err := engine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	// Backdate and pre-mark as escalated.
	conn := database.Conn()
	_, err = conn.ExecContext(ctx, `UPDATE approval_requests SET created_at = $2, escalated_at = $3 WHERE id = $1`,
		req.ID, time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	worker := governance.NewEscalationWorker(database, notifier, 100*time.Millisecond)
	worker.Start()
	time.Sleep(300 * time.Millisecond)
	worker.Stop()

	// Should NOT send another notification since it's already escalated.
	assert.Equal(t, 0, notifier.escalatedCount, "already-escalated request should not be re-notified")
}

func TestEscalationWorker_SkipsNonStaleRequests(t *testing.T) {
	database := setupTestDB(t)
	ctx := context.Background()

	org := &rbac.Organization{
		ID:                               uuid.New().String(),
		Slug:                             "test-esc-fresh-" + uuid.New().String()[:8],
		Name:                             "Escalation Fresh Test",
		Settings:                         map[string]any{},
		GovernanceEnabled:                true,
		ApprovalThreshold:                2,
		GovernanceEscalationTimeoutHours: 24, // 24 hours
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	requesterID := uuid.New().String()
	createTestUser(t, database, requesterID)

	notifier := &mockNotifier{}
	engine := governance.NewEngine(database, &mockApplier{}, notifier)

	// Create a fresh request (just now) — it should NOT be escalated.
	_, err := engine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	worker := governance.NewEscalationWorker(database, notifier, 100*time.Millisecond)
	worker.Start()
	time.Sleep(300 * time.Millisecond)
	worker.Stop()

	assert.Equal(t, 0, notifier.escalatedCount, "fresh request should not be escalated")
}

func TestAwaitingApproverIDFilter(t *testing.T) {
	database := setupTestDB(t)
	ctx := context.Background()

	org := createTestOrg(t, database)

	requesterID := uuid.New().String()
	approver1ID := uuid.New().String()
	approver2ID := uuid.New().String()
	createTestUser(t, database, requesterID)
	createTestUser(t, database, approver1ID)
	createTestUser(t, database, approver2ID)

	grantAdminClaim(t, database, org.ID, approver1ID)
	grantAdminClaim(t, database, org.ID, approver2ID)

	engine := governance.NewEngine(database, &mockApplier{}, &mockNotifier{})

	// Create two requests.
	req1, err := engine.SubmitChange(ctx, org.ID, requesterID, "change_a", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	req2, err := engine.SubmitChange(ctx, org.ID, requesterID, "change_b", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	// Approver1 votes on req1.
	_, err = engine.ProcessDecision(ctx, org.ID, req1.ID, approver1ID, "approve", nil)
	require.NoError(t, err)

	// AwaitingApproverID = approver1 should return only req2 (since approver1 already voted on req1).
	filter := db.ApprovalRequestFilter{AwaitingApproverID: &approver1ID}
	results, total, err := database.ListApprovalRequests(ctx, org.ID, 50, 0, filter)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, req2.ID, results[0].ID)

	// AwaitingApproverID = approver2 should return both (approver2 hasn't voted on either).
	filter2 := db.ApprovalRequestFilter{AwaitingApproverID: &approver2ID}
	results2, total2, err := database.ListApprovalRequests(ctx, org.ID, 50, 0, filter2)
	require.NoError(t, err)
	assert.Equal(t, 2, total2)
	assert.Len(t, results2, 2)
}

func TestAwaitingApproverIDFilter_ExcludesResolved(t *testing.T) {
	database := setupTestDB(t)
	ctx := context.Background()

	org := createTestOrg(t, database)

	requesterID := uuid.New().String()
	approverID := uuid.New().String()
	createTestUser(t, database, requesterID)
	createTestUser(t, database, approverID)

	grantAdminClaim(t, database, org.ID, approverID)

	engine := governance.NewEngine(database, &mockApplier{}, &mockNotifier{})

	// Create a request with threshold=1 and approve it.
	req, err := engine.SubmitChange(ctx, org.ID, requesterID, "change_resolved", nil, nil, json.RawMessage(`{}`), 1)
	require.NoError(t, err)

	_, err = engine.ProcessDecision(ctx, org.ID, req.ID, approverID, "approve", nil)
	require.NoError(t, err)

	// Another pending request.
	_, err = engine.SubmitChange(ctx, org.ID, requesterID, "change_pending", nil, nil, json.RawMessage(`{}`), 2)
	require.NoError(t, err)

	// AwaitingApproverID filter forces status=pending, so the approved request should not appear.
	filter := db.ApprovalRequestFilter{AwaitingApproverID: &approverID}
	results, total, err := database.ListApprovalRequests(ctx, org.ID, 50, 0, filter)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "change_pending", results[0].ChangeType)
}
