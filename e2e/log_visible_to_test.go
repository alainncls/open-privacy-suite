package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logVisibleToTestSetup holds IDs created during test setup.
type logVisibleToTestSetup struct {
	orgID         string
	groupID       string
	senderUserID  string
	senderDID     string
	viewerUserID  string
	viewerDID     string
	contractAddr  string
	senderAddr    string
	viewerAddr    string
}

// setupLogVisibleToTest creates the full RBAC hierarchy for testing logVisibleTo:
// org -> group -> sender user + viewer user -> contract with event rules -> grants.
func setupLogVisibleToTest(t *testing.T, database *db.DB) *logVisibleToTestSetup {
	t.Helper()
	ctx := context.Background()

	setup := &logVisibleToTestSetup{
		orgID:        uuid.New().String(),
		groupID:      uuid.New().String(),
		senderDID:    "did:privado:log_vis_sender",
		viewerDID:    "did:privado:log_vis_viewer",
		contractAddr: "0x6666666666666666666666666666666666666666",
		senderAddr:   "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		viewerAddr:   "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	// 1. Create organization
	org := &rbac.Organization{
		ID:       setup.orgID,
		Slug:     "log-vis-test-org",
		Name:     "Log Visibility Test Org",
		Settings: map[string]any{},
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	// 2. Create group with read+write claims
	group := &rbac.Group{
		ID:    setup.groupID,
		OrgID: setup.orgID,
		Slug:  "log-vis-group",
		Name:  "Log Visibility Group",
	}
	require.NoError(t, database.CreateGroup(ctx, group))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        setup.groupID,
		Claims:         []rbac.Claim{rbac.ClaimRead, rbac.ClaimWrite},
		AllowedMethods: []string{},
	}))

	// 3. Create sender user
	senderUser := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: setup.senderDID,
	}
	require.NoError(t, database.CreateUser(ctx, senderUser))
	setup.senderUserID = senderUser.ID
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  senderUser.ID,
		GroupID: setup.groupID,
	}))
	require.NoError(t, database.SystemLinkEthAddress(ctx, setup.senderDID, setup.senderAddr))

	// 4. Create viewer user
	viewerUser := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: setup.viewerDID,
	}
	require.NoError(t, database.CreateUser(ctx, viewerUser))
	setup.viewerUserID = viewerUser.ID
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  viewerUser.ID,
		GroupID: setup.groupID,
	}))
	require.NoError(t, database.SystemLinkEthAddress(ctx, setup.viewerDID, setup.viewerAddr))

	// 5. Create contract with event rules (Transfer with must_be=self on from param)
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	now := time.Now()
	contract := &rbac.Contract{
		ID:         uuid.New().String(),
		OrgID:      setup.orgID,
		Address:    setup.contractAddr,
		Name:       "Log Vis Test Token",
		DeployedAt: &now,
	}
	require.NoError(t, database.CreateContract(ctx, contract))

	// 6. Create grant with event rules
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    setup.groupID,
		EventRules: []rbac.EventRule{
			{
				Topic0: transferTopic0,
				Name:   "Transfer",
				ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "self"},
				},
			},
		},
	}))

	return setup
}

// TestLogVisibleToE2E_SaveAndQuery tests that logVisibleTo rules are stored
// and queried correctly at the database level.
func TestLogVisibleToE2E_SaveAndQuery(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	database, err := db.New(dbURL)
	require.NoError(t, err)
	defer database.Close()

	ctx := context.Background()
	setup := setupLogVisibleToTest(t, database)

	txHash := "0xfeedface0000000000000000000000000000000000000000000000000000abcd"

	// Save a logVisibleTo rule
	err = database.SaveTxLogVisibility(ctx, txHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID)
	require.NoError(t, err)

	// Query single
	dids, err := database.GetTxLogVisibility(ctx, txHash)
	require.NoError(t, err)
	assert.Equal(t, []string{setup.viewerDID}, dids)

	// Query batch
	batch, err := database.GetBatchTxLogVisibility(ctx, []string{txHash, "0xnonexistent"})
	require.NoError(t, err)
	assert.Len(t, batch, 1)
	assert.Equal(t, []string{setup.viewerDID}, batch[strings.ToLower(txHash)])

	// Verify the viewer DID is listed but unlisted user is not
	assert.Contains(t, dids, setup.viewerDID)
	assert.NotContains(t, dids, setup.senderDID)
}

// TestLogVisibleToE2E_FilterIntegration tests that the event filter uses
// logVisibleTo to extend access when param rules fail.
func TestLogVisibleToE2E_FilterIntegration(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	database, err := db.New(dbURL)
	require.NoError(t, err)
	defer database.Close()

	ctx := context.Background()
	setup := setupLogVisibleToTest(t, database)

	txHash := "0xfeedface0000000000000000000000000000000000000000000000000000def0"

	// Save logVisibleTo for viewer
	err = database.SaveTxLogVisibility(ctx, txHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID)
	require.NoError(t, err)

	// Query permissions for viewer (resolve effective permissions)
	// We build a minimal EffectivePermissions manually since we're testing
	// the filter, not the full permission resolver.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	senderTopic := "0x000000000000000000000000" + setup.senderAddr[2:]

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			setup.contractAddr: {
				Claims: []rbac.Claim{rbac.ClaimRead},
				EventRules: []rbac.EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				},
			},
		},
	}

	// Build log entry: Transfer event where from = sender (not viewer)
	logJSON := fmt.Sprintf(`{"address":"%s","topics":["%s","%s"],"data":"0x","transactionHash":"%s"}`,
		setup.contractAddr, transferTopic0, senderTopic, txHash)
	logs := []json.RawMessage{json.RawMessage(logJSON)}

	// Build visibility context
	visibility, err := database.GetBatchTxLogVisibility(ctx, []string{txHash})
	require.NoError(t, err)

	visCtx := &rbac.LogVisibilityContext{
		ViewerDID:    setup.viewerDID,
		TxVisibility: visibility,
	}

	// Viewer without logVisibleTo: should not see the log (not "self")
	resultWithout := rbac.FilterEventLogs(logs, perms, []string{setup.viewerAddr}, nil, nil)
	assert.Len(t, resultWithout, 0, "viewer should not see log without logVisibleTo")

	// Viewer with logVisibleTo: should see the log
	resultWith := rbac.FilterEventLogs(logs, perms, []string{setup.viewerAddr}, nil, visCtx)
	assert.Len(t, resultWith, 1, "viewer should see log with logVisibleTo")

	// Unlisted user with logVisibleTo context: should NOT see the log
	unlistedVisCtx := &rbac.LogVisibilityContext{
		ViewerDID:    "did:privado:unlisted",
		TxVisibility: visibility,
	}
	resultUnlisted := rbac.FilterEventLogs(logs, perms, []string{"0xcccccccccccccccccccccccccccccccccccccccc"}, nil, unlistedVisCtx)
	assert.Len(t, resultUnlisted, 0, "unlisted user should not see log even with visCtx")
}

// rpcCall is a helper for tests that makes a JSON-RPC call.
func rpcCall(t *testing.T, url string, method string, params []any, headers map[string]string) (int, json.RawMessage) {
	t.Helper()
	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, json.RawMessage(respBody)
}
