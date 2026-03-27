package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/governance"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopApplier is a test applier that always succeeds.
type noopApplier struct{}

func (n *noopApplier) ApplyGovernanceMutation(ctx context.Context, req *rbac.ApprovalRequest) error {
	return nil
}

// createAdminGroupAndMembership creates an admin group in the org and adds the user to it.
func createAdminGroupAndMembership(t *testing.T, srv *testServerRBAC, orgID, userID string) string {
	t.Helper()
	ctx := context.Background()
	adminGroupID := uuid.New().String()
	require.NoError(t, srv.db.CreateGroup(ctx, &rbac.Group{
		ID:        adminGroupID,
		OrgID:     orgID,
		Slug:      "admin-" + adminGroupID[:8],
		Name:      "Admin Group",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        adminGroupID,
		AllowedMethods: []string{"*"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:        uuid.New().String(),
		UserID:    userID,
		GroupID:   adminGroupID,
		Source:    rbac.MembershipSourceAdmin,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))
	return adminGroupID
}

func TestGovernanceApproverGroups_CRUD(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	org := createTestOrgWithGovernance(t, srv.db, true, 1)

	// Create a group in this org to designate as approver group
	approverGroupID := uuid.New().String()
	require.NoError(t, srv.db.CreateGroup(context.Background(), &rbac.Group{
		ID:        approverGroupID,
		OrgID:     org.ID,
		Slug:      "approvers-" + approverGroupID[:8],
		Name:      "Designated Approvers",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// Create admin API group with mock auth
	adminAPI := srv.router.Group("/test-approvers")
	adminAPI.Use(func(c *gin.Context) {
		c.Set("admin_user_id", uuid.New().String())
		c.Next()
	})
	adminAPI.GET("/orgs/:org_id/governance/approvers", srv.listGovernanceApproverGroups)
	adminAPI.POST("/orgs/:org_id/governance/approvers", srv.addGovernanceApproverGroup)
	adminAPI.DELETE("/orgs/:org_id/governance/approvers/:group_id", srv.removeGovernanceApproverGroup)

	t.Run("ListEmpty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test-approvers/orgs/"+org.ID+"/governance/approvers", nil)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		data := resp["data"].([]any)
		assert.Empty(t, data)
	})

	t.Run("Add", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"group_id": approverGroupID})
		req := httptest.NewRequest(http.MethodPost, "/test-approvers/orgs/"+org.ID+"/governance/approvers", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("AddDuplicate", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"group_id": approverGroupID})
		req := httptest.NewRequest(http.MethodPost, "/test-approvers/orgs/"+org.ID+"/governance/approvers", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		// Idempotent: ON CONFLICT DO NOTHING should not error
		require.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("AddGroupFromWrongOrg", func(t *testing.T) {
		otherOrgGroup := uuid.New().String()
		otherOrgID := uuid.New().String()
		require.NoError(t, srv.db.CreateOrganization(context.Background(), &rbac.Organization{
			ID:        otherOrgID,
			Slug:      "other-" + otherOrgID[:8],
			Name:      "Other Org",
			Settings:  map[string]any{},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}))
		require.NoError(t, srv.db.CreateGroup(context.Background(), &rbac.Group{
			ID:        otherOrgGroup,
			OrgID:     otherOrgID,
			Slug:      "other-group",
			Name:      "Other Group",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}))

		body, _ := json.Marshal(map[string]string{"group_id": otherOrgGroup})
		req := httptest.NewRequest(http.MethodPost, "/test-approvers/orgs/"+org.ID+"/governance/approvers", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("ListAfterAdd", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test-approvers/orgs/"+org.ID+"/governance/approvers", nil)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		data := resp["data"].([]any)
		require.Len(t, data, 1)

		entry := data[0].(map[string]any)
		assert.Equal(t, approverGroupID, entry["group_id"])
		assert.Equal(t, "Designated Approvers", entry["group_name"])
	})

	t.Run("Remove", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/test-approvers/orgs/"+org.ID+"/governance/approvers/"+approverGroupID, nil)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Verify it's gone
		groups, err := srv.db.ListGovernanceApproverGroups(context.Background(), org.ID)
		require.NoError(t, err)
		assert.Empty(t, groups)
	})

	t.Run("RemoveNonExistent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/test-approvers/orgs/"+org.ID+"/governance/approvers/"+uuid.New().String(), nil)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("RemoveFromWrongOrg", func(t *testing.T) {
		otherOrgID := uuid.New().String()
		require.NoError(t, srv.db.CreateOrganization(context.Background(), &rbac.Organization{
			ID:        otherOrgID,
			Slug:      "other-org-" + otherOrgID[:8],
			Name:      "Other Org",
			Settings:  map[string]any{},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}))

		req := httptest.NewRequest(http.MethodDelete, "/test-approvers/orgs/"+otherOrgID+"/governance/approvers/"+approverGroupID, nil)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestGovernanceApproverGroups_ApprovalEligibility(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	org := createTestOrgWithGovernance(t, srv.db, true, 1)
	ctx := context.Background()

	// Create users
	requesterID := uuid.New().String()
	adminUserID := uuid.New().String()
	approverUserID := uuid.New().String()
	nonApproverUserID := uuid.New().String()

	for _, id := range []string{requesterID, adminUserID, approverUserID, nonApproverUserID} {
		require.NoError(t, srv.db.CreateUser(ctx, &rbac.User{
			ID:         id,
			ExternalID: "did:test:" + id[:8],
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}))
	}

	// Create admin group + membership for adminUserID
	createAdminGroupAndMembership(t, srv, org.ID, adminUserID)

	// Create a designated approver group
	approverGroupID := uuid.New().String()
	require.NoError(t, srv.db.CreateGroup(ctx, &rbac.Group{
		ID:        approverGroupID,
		OrgID:     org.ID,
		Slug:      "designated-approvers",
		Name:      "Designated Approvers",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))
	// Add approverUserID to the designated approver group
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:        uuid.New().String(),
		UserID:    approverUserID,
		GroupID:   approverGroupID,
		Source:    rbac.MembershipSourceAdmin,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	srv.governanceEngine = governance.NewEngine(srv.db, &noopApplier{}, nil)

	t.Run("NoApproverGroups_AnyAdminCanApprove", func(t *testing.T) {
		// No approver groups configured yet -- any org admin should be able to approve
		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		result, err := srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, adminUserID, "approve", nil)
		require.NoError(t, err)
		assert.Equal(t, rbac.StatusApproved, result.Status)
	})

	t.Run("NoApproverGroups_NonAdminCannotApprove", func(t *testing.T) {
		// nonApproverUserID has no admin claim and no approver group membership
		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		_, err = srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, nonApproverUserID, "approve", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a designated approver")
	})

	// Now configure the designated approver group
	require.NoError(t, srv.db.AddGovernanceApproverGroup(ctx, org.ID, approverGroupID))

	t.Run("WithApproverGroups_MemberCanApprove", func(t *testing.T) {
		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		result, err := srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, approverUserID, "approve", nil)
		require.NoError(t, err)
		assert.Equal(t, rbac.StatusApproved, result.Status)
	})

	t.Run("WithApproverGroups_AdminCannotApprove", func(t *testing.T) {
		// adminUserID has admin claim but is NOT in the designated approver group
		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		_, err = srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, adminUserID, "approve", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a designated approver")
	})

	t.Run("WithApproverGroups_NonMemberCannotApprove", func(t *testing.T) {
		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		_, err = srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, nonApproverUserID, "approve", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a designated approver")
	})

	t.Run("WithApproverGroups_MemberCanReject", func(t *testing.T) {
		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		reason := "Not appropriate"
		result, err := srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, approverUserID, "reject", &reason)
		require.NoError(t, err)
		assert.Equal(t, rbac.StatusRejected, result.Status)
	})

	t.Run("RemoveApproverGroup_FallsBackToAdmin", func(t *testing.T) {
		// Remove the approver group -- should fall back to "any admin" behavior
		require.NoError(t, srv.db.RemoveGovernanceApproverGroup(ctx, org.ID, approverGroupID))

		req, err := srv.governanceEngine.SubmitChange(ctx, org.ID, requesterID, "test_change", nil, nil, json.RawMessage(`{}`), 1)
		require.NoError(t, err)

		result, err := srv.governanceEngine.ProcessDecision(ctx, org.ID, req.ID, adminUserID, "approve", nil)
		require.NoError(t, err)
		assert.Equal(t, rbac.StatusApproved, result.Status)
	})
}

func TestGovernanceSettings_IncludesApproverGroups(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	org := createTestOrgWithGovernance(t, srv.db, true, 1)
	ctx := context.Background()

	// Create a group and designate it as approver
	groupID := uuid.New().String()
	require.NoError(t, srv.db.CreateGroup(ctx, &rbac.Group{
		ID:        groupID,
		OrgID:     org.ID,
		Slug:      "settings-approvers",
		Name:      "Settings Approvers",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, srv.db.AddGovernanceApproverGroup(ctx, org.ID, groupID))

	// Register GET settings endpoint with mock auth
	testAPI := srv.router.Group("/test-settings")
	testAPI.GET("/orgs/:org_id/governance/settings", srv.getGovernanceSettings)

	req := httptest.NewRequest(http.MethodGet, "/test-settings/orgs/"+org.ID+"/governance/settings", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, true, resp["governance_enabled"])
	assert.NotNil(t, resp["approver_groups"])
	groups := resp["approver_groups"].([]any)
	require.Len(t, groups, 1)
	assert.Equal(t, groupID, groups[0].(map[string]any)["group_id"])
}
