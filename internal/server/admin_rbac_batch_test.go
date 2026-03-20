package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchMoveContracts(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-move-org")

	// Create 2 auto-created groups via direct DB insertion
	autoGroup1 := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-group-1",
		Name:        "Auto Group 1",
		Depth:       0,
		Path:        "auto-group-1",
		AutoCreated: true,
	}
	autoGroup2 := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-group-2",
		Name:        "Auto Group 2",
		Depth:       0,
		Path:        "auto-group-2",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup1))
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup2))

	// Create group access with deploy claims for both auto groups
	for _, g := range []*rbac.Group{autoGroup1, autoGroup2} {
		require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        g.ID,
			AllowedMethods: []string{"*"},
			Claims:         []rbac.Claim{rbac.ClaimDeploy, rbac.ClaimRead, rbac.ClaimWrite},
		}))
	}

	// Create 2 contracts
	addr1 := "0x1111111111111111111111111111111111111111"
	addr2 := "0x2222222222222222222222222222222222222222"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Contract 1")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Contract 2")

	// Create contract grants linking each contract to its auto-created group
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    autoGroup1.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    autoGroup2.ID,
	}))

	// Call batch-move
	body := map[string]any{
		"contract_ids": []string{contractID1, contractID2},
		"new_group": map[string]any{
			"slug": "production",
			"name": "Production",
		},
		"delete_empty_auto_groups": true,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, float64(2), result["moved_count"])
	assert.NotEmpty(t, result["target_group_id"])

	targetGroupID := result["target_group_id"].(string)

	// Verify the new group was created
	targetGroup, err := server.db.GetGroup(ctx, targetGroupID)
	require.NoError(t, err)
	require.NotNil(t, targetGroup)
	assert.Equal(t, "production", targetGroup.Slug)
	assert.Equal(t, "Production", targetGroup.Name)

	// Verify auto-created groups were deleted (they should be empty now)
	deletedGroup1, err := server.db.GetGroup(ctx, autoGroup1.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedGroup1)

	deletedGroup2, err := server.db.GetGroup(ctx, autoGroup2.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedGroup2)

	// Verify contracts now have grants to the new target group
	grants1, err := server.db.ListContractGrantsByContract(ctx, contractID1)
	require.NoError(t, err)
	require.Len(t, grants1, 1)
	assert.Equal(t, targetGroupID, grants1[0].GroupID)

	grants2, err := server.db.ListContractGrantsByContract(ctx, contractID2)
	require.NoError(t, err)
	require.Len(t, grants2, 1)
	assert.Equal(t, targetGroupID, grants2[0].GroupID)
}

func TestBatchMovePreservesManualGrants(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-preserve-org")

	// Create a manual group via API
	manualGroup := createTestGroup(t, server, org.ID, "manual-group")

	// Create an auto-created group via direct DB
	autoGroup := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-preserve",
		Name:        "Auto Preserve",
		Depth:       0,
		Path:        "auto-preserve",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup))
	require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        autoGroup.ID,
		AllowedMethods: []string{"*"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy, rbac.ClaimRead, rbac.ClaimWrite},
	}))

	// Create a contract with grants to both groups
	addr := "0x3333333333333333333333333333333333333333"
	contractID := createTestContract(t, server, org.ID, addr, "Dual Grant Contract")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    manualGroup.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    autoGroup.ID,
	}))

	// Call batch-move to a new target group
	body := map[string]any{
		"contract_ids": []string{contractID},
		"new_group": map[string]any{
			"slug": "target-preserve",
			"name": "Target Preserve",
		},
		"delete_empty_auto_groups": true,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	targetGroupID := result["target_group_id"].(string)

	// Verify the manual grant still exists alongside the new target grant
	grants, err := server.db.ListContractGrantsByContract(ctx, contractID)
	require.NoError(t, err)

	groupIDs := make(map[string]bool)
	for _, g := range grants {
		groupIDs[g.GroupID] = true
	}

	assert.True(t, groupIDs[manualGroup.ID], "manual grant should still exist")
	assert.True(t, groupIDs[targetGroupID], "new target grant should exist")
	assert.False(t, groupIDs[autoGroup.ID], "auto-created group grant should be removed")
}

func TestBatchMoveDoesNotDeleteNonEmptyAutoGroups(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-nonempty-org")

	// Create an auto-created group with 2 contracts
	autoGroup := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-nonempty",
		Name:        "Auto Non-Empty",
		Depth:       0,
		Path:        "auto-nonempty",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup))
	require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        autoGroup.ID,
		AllowedMethods: []string{"*"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy, rbac.ClaimRead, rbac.ClaimWrite},
	}))

	addr1 := "0x4444444444444444444444444444444444444444"
	addr2 := "0x5555555555555555555555555555555555555555"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Contract Stay")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Contract Move")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    autoGroup.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    autoGroup.ID,
	}))

	// Batch-move only 1 contract
	body := map[string]any{
		"contract_ids": []string{contractID2},
		"new_group": map[string]any{
			"slug": "target-nonempty",
			"name": "Target Non-Empty",
		},
		"delete_empty_auto_groups": true,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the auto-created group still exists (it still has 1 contract)
	group, err := server.db.GetGroup(ctx, autoGroup.ID)
	require.NoError(t, err)
	assert.NotNil(t, group, "auto-created group should still exist because it still has contracts")
}

func TestBatchMoveCrossOrgRejection(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org1 := createTestOrganization(t, server, "batch-cross-org1")
	org2 := createTestOrganization(t, server, "batch-cross-org2")

	addr := "0x6666666666666666666666666666666666666666"
	contractID := createTestContract(t, server, org1.ID, addr, "Cross Org Contract")

	// Try to batch-move org1's contract under org2
	body := map[string]any{
		"contract_ids": []string{contractID},
		"new_group": map[string]any{
			"slug": "stolen-group",
			"name": "Stolen Group",
		},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org2.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Contains(t, result["error"], "does not belong")
}

func TestBatchDeleteGroups(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-delete-org")

	// Create 2 groups with access, memberships, and grants
	group1 := createTestGroup(t, server, org.ID, "delete-group-1")
	group2 := createTestGroup(t, server, org.ID, "delete-group-2")

	// Add access to both groups
	for _, g := range []*rbac.Group{group1, group2} {
		require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        g.ID,
			AllowedMethods: []string{"eth_call"},
			Claims:         []rbac.Claim{rbac.ClaimRead},
		}))
	}

	// Create a user and memberships
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:batch-delete-user",
		Metadata:   map[string]any{},
	}
	require.NoError(t, server.db.CreateUser(ctx, user))

	for _, g := range []*rbac.Group{group1, group2} {
		require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: g.ID,
			Source:  rbac.MembershipSourceAdmin,
		}))
	}

	// Create contracts and grants
	addr1 := "0x7777777777777777777777777777777777777777"
	addr2 := "0x8888888888888888888888888888888888888888"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Delete Contract 1")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Delete Contract 2")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    group1.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    group2.ID,
	}))

	// Call batch-delete
	body := map[string]any{
		"group_ids": []string{group1.ID, group2.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, float64(2), result["deleted_count"])

	// Verify groups are gone
	g1, err := server.db.GetGroup(ctx, group1.ID)
	require.NoError(t, err)
	assert.Nil(t, g1)

	g2, err := server.db.GetGroup(ctx, group2.ID)
	require.NoError(t, err)
	assert.Nil(t, g2)
}

func TestBatchDeletePreview(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-preview-org")

	// Create an auto group and a manual group
	autoGroup := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "preview-auto",
		Name:        "Preview Auto",
		Depth:       0,
		Path:        "preview-auto",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup))

	manualGroup := createTestGroup(t, server, org.ID, "preview-manual")

	// Add contracts and members to both
	addr1 := "0x9999999999999999999999999999999999999999"
	addr2 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Preview Contract 1")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Preview Contract 2")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    autoGroup.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    manualGroup.ID,
	}))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:preview-user",
		Metadata:   map[string]any{},
	}
	require.NoError(t, server.db.CreateUser(ctx, user))
	require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: autoGroup.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	// Call batch-delete-preview
	body := map[string]any{
		"group_ids": []string{autoGroup.ID, manualGroup.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete-preview", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))

	groups := result["groups"].([]any)
	require.Len(t, groups, 2)

	// Build a map by ID for easier assertions
	previews := make(map[string]map[string]any)
	for _, g := range groups {
		gm := g.(map[string]any)
		previews[gm["id"].(string)] = gm
	}

	// Auto group: 1 contract, 1 member, auto_created=true
	autoPreview := previews[autoGroup.ID]
	require.NotNil(t, autoPreview)
	assert.Equal(t, true, autoPreview["auto_created"])
	assert.Equal(t, float64(1), autoPreview["contract_count"])
	assert.Equal(t, float64(1), autoPreview["member_count"])

	// Manual group: 1 contract, 0 members, auto_created=false
	manualPreview := previews[manualGroup.ID]
	require.NotNil(t, manualPreview)
	assert.Equal(t, false, manualPreview["auto_created"])
	assert.Equal(t, float64(1), manualPreview["contract_count"])
	assert.Equal(t, float64(0), manualPreview["member_count"])
}

func TestBatchDeleteCrossOrgRejection(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org1 := createTestOrganization(t, server, "batch-del-cross-org1")
	org2 := createTestOrganization(t, server, "batch-del-cross-org2")

	group := createTestGroup(t, server, org1.ID, "cross-org-group")

	// Try to batch-delete org1's group under org2
	body := map[string]any{
		"group_ids": []string{group.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete", org2.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Contains(t, result["error"], "not found")
}

func TestGroupListFilterByAutoCreated(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "filter-auto-org")

	// Create 2 auto-created groups via direct DB
	for i := 1; i <= 2; i++ {
		slug := fmt.Sprintf("auto-filter-%d", i)
		require.NoError(t, server.db.CreateGroup(ctx, &rbac.Group{
			ID:          uuid.New().String(),
			OrgID:       org.ID,
			Slug:        slug,
			Name:        fmt.Sprintf("Auto Filter %d", i),
			Depth:       0,
			Path:        slug,
			AutoCreated: true,
		}))
	}

	// Create 1 manual group via API
	createTestGroup(t, server, org.ID, "manual-filter")

	t.Run("FilterAutoCreatedTrue", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups?auto_created=true", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		data := result["data"].([]any)
		assert.Equal(t, 2, len(data))
	})

	t.Run("FilterAutoCreatedFalse", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups?auto_created=false", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		data := result["data"].([]any)
		assert.Equal(t, 1, len(data))
	})

	t.Run("NoFilter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		data := result["data"].([]any)
		assert.Equal(t, 3, len(data))
	})
}

func TestCreateDeployerAutoGrants(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "deployer-auto-org")

	// Create a user
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:deployer-auto",
		Metadata:   map[string]any{},
	}
	require.NoError(t, server.db.CreateUser(ctx, user))

	// Create a contract
	addr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc"
	contractID := createTestContract(t, server, org.ID, addr, "Auto Grant Contract")

	// Call CreateDeployerAutoGrants directly
	group, err := server.db.CreateDeployerAutoGrants(ctx, db.DeployerAutoGrantParams{
		OrgID:              org.ID,
		ContractID:         contractID,
		DeployerUserID:     user.ID,
		DeployerExternalID: user.ExternalID,
	})
	require.NoError(t, err)
	require.NotNil(t, group)

	// Verify the group was created with auto_created: true
	fetchedGroup, err := server.db.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.NotNil(t, fetchedGroup)
	assert.True(t, fetchedGroup.AutoCreated)

	// Verify group access has deploy claims
	access, err := server.db.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	require.NotNil(t, access)

	claimSet := make(map[rbac.Claim]bool)
	for _, c := range access.Claims {
		claimSet[c] = true
	}
	assert.True(t, claimSet[rbac.ClaimDeploy], "should have deploy claim")
	assert.True(t, claimSet[rbac.ClaimRead], "should have read claim (expanded)")
	assert.True(t, claimSet[rbac.ClaimWrite], "should have write claim (expanded)")

	// Verify user has membership in the group
	members, err := server.db.ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, user.ID, members[0].UserID)

	// Verify contract has a grant to the group
	grants, err := server.db.ListContractGrantsByContract(ctx, contractID)
	require.NoError(t, err)

	found := false
	for _, g := range grants {
		if g.GroupID == group.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "contract should have a grant to the auto-created group")
}
