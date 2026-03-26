package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/server"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test addresses and DIDs for E2E tests
const (
	e2eViewerWallet  = "0x1111111111111111111111111111111111111111"
	e2eTargetAddress = "0x2222222222222222222222222222222222222222"
	e2ePublicAddress = "0x3333333333333333333333333333333333333333"
	e2eUnknownWallet = "0x4444444444444444444444444444444444444444"
	e2eViewerDID     = "did:privado:e2e_viewer"
	e2eTargetDID     = "did:privado:e2e_target"
)

// explorerTestSetup creates the necessary test data for explorer E2E tests
type explorerTestSetup struct {
	viewerUserID string
	targetUserID string
}

func setupExplorerTestData(t *testing.T, database *db.DB) *explorerTestSetup {
	ctx := context.Background()
	setup := &explorerTestSetup{}

	// Create default organization
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// Create viewer user
	setup.viewerUserID = uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, true, false, '{}')",
		setup.viewerUserID, e2eViewerDID)
	require.NoError(t, err)

	// Create target user
	setup.targetUserID = uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, true, false, '{}')",
		setup.targetUserID, e2eTargetDID)
	require.NoError(t, err)

	return setup
}

func linkAddressForE2E(t *testing.T, database *db.DB, did, address string) {
	err := database.LinkEthAddress(context.Background(), did, address, "test-sig", "test-hash-"+address)
	require.NoError(t, err)
}

func createDisclosureGrantForE2E(t *testing.T, database *db.DB, requesterDID, targetUserID string, expiresAt time.Time) string {
	ctx := context.Background()

	// Create disclosure request
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, '00000000-0000-0000-0000-000000000001', '{}', 'E2E test grant', 'approved', NOW())`,
		requestID, requesterDID, targetUserID)
	require.NoError(t, err)

	// Create grant
	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, '{}', NOW(), $4)`,
		grantID, requestID, "e2e-test-hash-"+grantID, expiresAt)
	require.NoError(t, err)

	return grantID
}

// ============================================================================
// E2E Test: Own Address Visibility
// ============================================================================

func TestE2E_Explorer_OwnAddressVisible(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setupExplorerTestData(t, database)

	// Link viewer's address
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)

	// Check visibility via HTTP (note: explorer API is localhost-only, so we connect via localhost)
	client := &http.Client{Timeout: 5 * time.Second}

	// Check own address visibility
	checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eViewerWallet + "?wallet=" + e2eViewerWallet
	req, _ := http.NewRequest("GET", checkURL, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1") // Localhost for explorer API

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.CheckAddressResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.True(t, result.Visible)
	assert.Equal(t, server.ReasonOwnAddress, result.Reason)
	assert.Equal(t, server.VisibilityFull, result.Level)
}

// ============================================================================
// E2E Test: Disclosure Grant Flow
// ============================================================================

func TestE2E_Explorer_DisclosureGrantFlow(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link addresses
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)
	linkAddressForE2E(t, database, e2eTargetDID, e2eTargetAddress)

	client := &http.Client{Timeout: 5 * time.Second}

	// Step 1: Initially no access — G16 oracle masking makes non-visible
	// addresses indistinguishable from genuinely public (unregistered) ones.
	t.Run("initially no access", func(t *testing.T) {
		checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
		req, _ := http.NewRequest("GET", checkURL, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		var result server.CheckAddressResponse
		json.Unmarshal(body, &result)

		assert.True(t, result.Visible)
		assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	})

	// Step 2: Create disclosure grant
	grantID := createDisclosureGrantForE2E(t, database, e2eViewerDID, setup.targetUserID, time.Now().Add(24*time.Hour))

	// Step 3: Now should have access
	t.Run("access granted", func(t *testing.T) {
		checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
		req, _ := http.NewRequest("GET", checkURL, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		var result server.CheckAddressResponse
		json.Unmarshal(body, &result)

		// G17: Disclosure grants do NOT upgrade visibility in check-addresses.
		// G16: Non-visible addresses are then masked as public (oracle prevention).
		assert.True(t, result.Visible, "G16: non-visible masked as public")
		assert.Equal(t, server.ReasonPublicAddress, result.Reason, "G16: reason masked as public_address")
		assert.Equal(t, server.VisibilityFull, result.Level)
		assert.Nil(t, result.GrantID, "grant metadata must not leak via check-addresses")
	})

	// Step 4: Revoke grant
	ctx := context.Background()
	_, err := database.Conn().ExecContext(ctx,
		"UPDATE disclosure_grants SET revoked_at = NOW(), revoked_reason = 'test revocation' WHERE id = $1",
		grantID)
	require.NoError(t, err)

	// Step 5: Access revoked — G16 oracle masking: looks like public_address again.
	t.Run("access revoked", func(t *testing.T) {
		checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
		req, _ := http.NewRequest("GET", checkURL, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		var result server.CheckAddressResponse
		json.Unmarshal(body, &result)

		assert.True(t, result.Visible)
		assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	})
}

// ============================================================================
// E2E Test: Public Address
// ============================================================================

func TestE2E_Explorer_PublicAddress(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setupExplorerTestData(t, database)

	// Link viewer's address
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)

	// Public address is NOT linked to any DID
	client := &http.Client{Timeout: 5 * time.Second}

	checkURL := serverURL + "/api/v1/explorer/check-address/" + e2ePublicAddress + "?wallet=" + e2eViewerWallet
	req, _ := http.NewRequest("GET", checkURL, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.CheckAddressResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.True(t, result.Visible)
	assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	assert.Equal(t, server.VisibilityFull, result.Level)
}

// ============================================================================
// E2E Test: No Access Without Grant
// ============================================================================

func TestE2E_Explorer_NoAccessWithoutGrant(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setupExplorerTestData(t, database)

	// Link addresses
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)
	linkAddressForE2E(t, database, e2eTargetDID, e2eTargetAddress)

	// No grant created

	client := &http.Client{Timeout: 5 * time.Second}

	checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
	req, _ := http.NewRequest("GET", checkURL, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.CheckAddressResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// G16 oracle masking: non-visible addresses are indistinguishable from public ones.
	assert.True(t, result.Visible)
	assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	assert.Equal(t, server.VisibilityFull, result.Level)
}

// ============================================================================
// E2E Test: Batch Check
// ============================================================================

func TestE2E_Explorer_BatchCheck(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link addresses
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)
	linkAddressForE2E(t, database, e2eTargetDID, e2eTargetAddress)

	// Create grant for target address
	createDisclosureGrantForE2E(t, database, e2eViewerDID, setup.targetUserID, time.Now().Add(24*time.Hour))

	// G16: Batch endpoint now requires JWT auth.
	accessToken := getJWTToken(t, serverURL, e2eViewerDID)

	client := &http.Client{Timeout: 5 * time.Second}

	// Batch check: own address, granted address, public address
	batchBody := map[string][]string{
		"addresses": {e2eViewerWallet, e2eTargetAddress, e2ePublicAddress},
	}
	jsonBody, _ := json.Marshal(batchBody)

	req, _ := http.NewRequest("POST", serverURL+"/api/v1/explorer/check-addresses?wallet="+e2eViewerWallet, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.BatchCheckAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Len(t, result.Results, 3)

	// Own address
	assert.True(t, result.Results[e2eViewerWallet].Visible)
	assert.Equal(t, server.ReasonOwnAddress, result.Results[e2eViewerWallet].Reason)

	// Granted address — G17: check-address does not reveal disclosure grants.
	// G16 oracle masking then makes this look like a public address.
	assert.True(t, result.Results[e2eTargetAddress].Visible)
	assert.Equal(t, server.ReasonPublicAddress, result.Results[e2eTargetAddress].Reason)

	// Public address
	assert.True(t, result.Results[e2ePublicAddress].Visible)
	assert.Equal(t, server.ReasonPublicAddress, result.Results[e2ePublicAddress].Reason)
}

// ============================================================================
// E2E Test: Viewable Addresses
// ============================================================================

func TestE2E_Explorer_ViewableAddresses(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link addresses
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)
	linkAddressForE2E(t, database, e2eTargetDID, e2eTargetAddress)

	// Create grant
	createDisclosureGrantForE2E(t, database, e2eViewerDID, setup.targetUserID, time.Now().Add(24*time.Hour))

	client := &http.Client{Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", serverURL+"/api/v1/explorer/viewable-addresses?wallet="+e2eViewerWallet, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.ViewableAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, e2eViewerWallet, result.ViewerWallet)
	assert.Equal(t, e2eViewerDID, result.ViewerDID)
	assert.Len(t, result.OwnAddresses, 1)
	assert.Equal(t, e2eViewerWallet, result.OwnAddresses[0].Address)
	assert.Len(t, result.DisclosedAddresses, 1)
	assert.Equal(t, e2eTargetAddress, result.DisclosedAddresses[0].Address)
	assert.Equal(t, e2eTargetDID, result.DisclosedAddresses[0].OwnerDID)
}

// ============================================================================
// E2E Test: Anonymous Viewer
// ============================================================================

func TestE2E_Explorer_AnonymousViewer(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	client := &http.Client{Timeout: 5 * time.Second}

	// Anonymous wallet (not linked to any DID)
	req, _ := http.NewRequest("GET", serverURL+"/api/v1/explorer/viewable-addresses?wallet="+e2eUnknownWallet, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.ViewableAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, e2eUnknownWallet, result.ViewerWallet)
	assert.Empty(t, result.ViewerDID)
	assert.Empty(t, result.OwnAddresses)
	assert.Empty(t, result.DisclosedAddresses)
}

// ============================================================================
// E2E Test: Full Integration with Disclosure Service
// ============================================================================

func TestE2E_Explorer_FullIntegrationWithDisclosureService(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link addresses
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)
	linkAddressForE2E(t, database, e2eTargetDID, e2eTargetAddress)

	client := &http.Client{Timeout: 5 * time.Second}

	// Step 1: Verify no access initially — G16 oracle masking makes this look public.
	t.Run("no access initially", func(t *testing.T) {
		checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
		req, _ := http.NewRequest("GET", checkURL, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		var result server.CheckAddressResponse
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &result)

		assert.True(t, result.Visible)
		assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	})

	// Step 2: Create disclosure request using the disclosure service
	disclosureService := disclosure.NewService(database)
	ctx := context.Background()

	request, err := disclosureService.CreateRequest(
		ctx,
		"",
		e2eViewerDID,
		setup.targetUserID,
		"00000000-0000-0000-0000-000000000001",
		disclosure.Scope{},
		"E2E test request",
		"",
		nil,
	)
	require.NoError(t, err)

	// Step 3: Approve the request (simulating target user approval)
	grant, err := disclosureService.ApproveRequest(
		ctx,
		request.ID,
		setup.targetUserID,
		nil,
		24*time.Hour,
		"Approved for E2E test",
	)
	require.NoError(t, err)

	// Step 4: Verify access is now granted
	t.Run("access granted after approval", func(t *testing.T) {
		checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
		req, _ := http.NewRequest("GET", checkURL, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		var result server.CheckAddressResponse
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &result)

		// G17: check-address does not reveal disclosure grants.
		// G16: non-visible addresses masked as public (oracle prevention).
		assert.True(t, result.Visible)
		assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	})

	// Step 5: Revoke using disclosure service
	err = disclosureService.RevokeGrant(ctx, grant.ID, "E2E test revocation")
	require.NoError(t, err)

	// Step 6: Verify access is revoked — G16 oracle masking: looks like public_address again.
	t.Run("access revoked after revocation", func(t *testing.T) {
		checkURL := serverURL + "/api/v1/explorer/check-address/" + e2eTargetAddress + "?wallet=" + e2eViewerWallet
		req, _ := http.NewRequest("GET", checkURL, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		var result server.CheckAddressResponse
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &result)

		assert.True(t, result.Visible)
		assert.Equal(t, server.ReasonPublicAddress, result.Reason)
	})
}

// ============================================================================
// E2E Test: Multiple Addresses Per User
// ============================================================================

func TestE2E_Explorer_MultipleAddressesPerUser(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link multiple addresses to viewer
	addresses := []string{
		"0xaaaa111111111111111111111111111111111111",
		"0xaaaa222222222222222222222222222222222222",
		"0xaaaa333333333333333333333333333333333333",
	}

	for _, addr := range addresses {
		linkAddressForE2E(t, database, e2eViewerDID, addr)
	}

	// Link multiple addresses to target
	targetAddresses := []string{
		"0xbbbb111111111111111111111111111111111111",
		"0xbbbb222222222222222222222222222222222222",
	}

	for _, addr := range targetAddresses {
		linkAddressForE2E(t, database, e2eTargetDID, addr)
	}

	// Create grant
	createDisclosureGrantForE2E(t, database, e2eViewerDID, setup.targetUserID, time.Now().Add(24*time.Hour))

	client := &http.Client{Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", serverURL+"/api/v1/explorer/viewable-addresses?wallet="+addresses[0], nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result server.ViewableAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Len(t, result.OwnAddresses, 3)
	assert.Len(t, result.DisclosedAddresses, 2)

	// Verify all own addresses are present
	ownAddressMap := make(map[string]bool)
	for _, a := range result.OwnAddresses {
		ownAddressMap[a.Address] = true
	}
	for _, addr := range addresses {
		assert.True(t, ownAddressMap[addr], "Expected address %s to be in own addresses", addr)
	}

	// Verify all disclosed addresses are present
	disclosedAddressMap := make(map[string]bool)
	for _, a := range result.DisclosedAddresses {
		disclosedAddressMap[a.Address] = true
	}
	for _, addr := range targetAddresses {
		assert.True(t, disclosedAddressMap[addr], "Expected address %s to be in disclosed addresses", addr)
	}
}
