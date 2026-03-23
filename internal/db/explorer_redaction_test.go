package db

import (
	"context"
	"testing"

	"privacy-proxy/internal/explorer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOrgContract inserts an org, group, contract, and contract_grant.
// Returns the contractID and groupID for further assertions.
func setupOrgContract(t *testing.T, database *DB, contractAddr string) (contractID, groupID string) {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "redaction-org-"+orgID[:8], "Redaction Test Org")
	require.NoError(t, err)

	groupID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)

	contractID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		contractID, orgID, contractAddr, "Redaction Test Contract")
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	return contractID, groupID
}

// addMember inserts a user with the given DID and adds them to groupID.
func addMember(t *testing.T, database *DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, did)
	require.NoError(t, err)
	_, err = database.Conn().ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')",
		uuid.New().String(), userID, groupID)
	require.NoError(t, err)
	return userID
}

// addExpiredMember inserts a user with an already-expired membership.
func addExpiredMember(t *testing.T, database *DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, did)
	require.NoError(t, err)
	_, err = database.Conn().ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source, expires_at) VALUES ($1, $2, $3, 'admin', NOW() - INTERVAL '1 day')",
		uuid.New().String(), userID, groupID)
	require.NoError(t, err)
	return userID
}

// ============================================================================
// GetBatchVisibility — org contract visibility
// ============================================================================

func TestGetBatchVisibility_OrgContract(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	const privateAddr = "0xaaaa000000000000000000000000000000000001"
	_, groupID := setupOrgContract(t, database, privateAddr)

	ctx := context.Background()

	t.Run("anonymous viewer sees Redacted not Hidden", func(t *testing.T) {
		// Anonymous (empty DID) should get VisibilityRedacted, not Hidden.
		// This ensures transactions involving the address show [PRIVATE] rather than being dropped.
		visMap, err := database.GetBatchVisibility(ctx, "", []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr],
			"org contract must be VisibilityRedacted for anonymous viewer (not Hidden)")
	})

	t.Run("non-member sees Redacted", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, "did:privado:outsider_batch", []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr])
	})

	t.Run("standard member sees Redacted", func(t *testing.T) {
		const memberDID = "did:privado:batch_member"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr],
			"standard group member must ONLY have VisibilityRedacted for org contract")
	})

	t.Run("admin member sees Full", func(t *testing.T) {
		const adminDID = "did:privado:admin_member"
		
		// Create an admin group
		adminGroupID := uuid.New().String()
		_, err := database.Conn().ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins', 'Admins', 0, 'admins', true)",
			adminGroupID, groupID)
		require.NoError(t, err)
		
		addMember(t, database, adminDID, adminGroupID)

		visMap, err := database.GetBatchVisibility(ctx, adminDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"admin group member must have VisibilityFull for their org contract")
	})

	t.Run("contract admin via grant sees Full", func(t *testing.T) {
		const grantAdminDID = "did:privado:grant_admin_member"

		// Create a NON-org-admin group in the same org.
		grantGroupID := uuid.New().String()
		_, err := database.Conn().ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'grant-admins', 'Grant Admins', 0, 'grant-admins', false)",
			grantGroupID, groupID)
		require.NoError(t, err)

		// Create a contract_grant linking the non-admin group to the contract with claims = '{admin}'.
		// First we need the contract ID for privateAddr.
		var contractID string
		err = database.Conn().QueryRowContext(ctx,
			"SELECT id FROM contracts WHERE LOWER(address) = $1", privateAddr).Scan(&contractID)
		require.NoError(t, err)

		_, err = database.Conn().ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{admin}')",
			uuid.New().String(), contractID, grantGroupID)
		require.NoError(t, err)

		addMember(t, database, grantAdminDID, grantGroupID)

		visMap, err := database.GetBatchVisibility(ctx, grantAdminDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"member of non-admin group with 'admin' contract_grant claim must have VisibilityFull")
	})

	t.Run("expired member sees Redacted", func(t *testing.T) {
		const expiredDID = "did:privado:expired_batch"
		addExpiredMember(t, database, expiredDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, expiredDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr],
			"expired member must not retain access after expiry")
	})

	t.Run("public address not affected", func(t *testing.T) {
		const publicAddr = "0x9999000000000000000000000000000000000001"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{publicAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[publicAddr],
			"public address (not in contracts table) must remain VisibilityFull")
	})

	t.Run("mixed batch: public and private", func(t *testing.T) {
		const publicAddr = "0x9999000000000000000000000000000000000002"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{privateAddr, publicAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr])
		assert.Equal(t, explorer.VisibilityFull, visMap[publicAddr])
	})
}

// TestGetBatchVisibility_NoAdminGroups verifies that org contracts are
// VisibilityRedacted even when no admin groups exist at all. Regression test
// for the bug where org contract detection was coupled with admin group lookup —
// if no admin groups existed, the contract fell through as VisibilityFull.
func TestGetBatchVisibility_NoAdminGroups(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "no-admin-org", "No Admin Org")
	require.NoError(t, err)

	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'readers', 'Readers', 0, 'readers', false)",
		groupID, orgID)
	require.NoError(t, err)

	contractAddr := "0xbbbb000000000000000000000000000000000099"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'No Admin Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{read}')",
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	t.Run("anonymous sees Redacted", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"org contract must be Redacted for anonymous even with no admin groups")
	})

	t.Run("read-only member sees Redacted", func(t *testing.T) {
		memberDID := "did:test:reader_no_admin"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"read-only member must see Redacted when no admin groups exist")
	})
}

func TestGetBatchVisibility_EdgeCases(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	t.Run("cross-org admin cannot see other org contracts as Full", func(t *testing.T) {
		// Org A: admin group + contract
		orgAID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgAID, "edge-orgA-"+orgAID[:8], "Edge Org A")
		require.NoError(t, err)

		adminGroupA := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
			adminGroupA, orgAID)
		require.NoError(t, err)

		contractAAddr := "0xaa01000000000000000000000000000000000001"
		contractAID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract A')",
			contractAID, orgAID, contractAAddr)
		require.NoError(t, err)

		// Org B: contract only (no admin groups needed for this test)
		orgBID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgBID, "edge-orgB-"+orgBID[:8], "Edge Org B")
		require.NoError(t, err)

		contractBAddr := "0xbb01000000000000000000000000000000000001"
		contractBID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract B')",
			contractBID, orgBID, contractBAddr)
		require.NoError(t, err)

		// User is admin of Org A
		const crossAdminDID = "did:test:cross_org_admin"
		addMember(t, database, crossAdminDID, adminGroupA)

		visMap, err := database.GetBatchVisibility(ctx, crossAdminDID, []string{contractAAddr, contractBAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAAddr],
			"admin of Org A must see own org contract as Full")
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractBAddr],
			"admin of Org A must NOT see Org B contract as Full — cross-org isolation")
	})

	t.Run("deploy claim does not grant Full", func(t *testing.T) {
		orgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgID, "edge-deploy-"+orgID[:8], "Deploy Org")
		require.NoError(t, err)

		groupID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'deployers', 'Deployers', 0, 'deployers', false)",
			groupID, orgID)
		require.NoError(t, err)

		contractAddr := "0xdd01000000000000000000000000000000000001"
		contractID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Deploy Contract')",
			contractID, orgID, contractAddr)
		require.NoError(t, err)

		_, err = conn.ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{deploy}')",
			uuid.New().String(), contractID, groupID)
		require.NoError(t, err)

		const deployDID = "did:test:deploy_member"
		addMember(t, database, deployDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, deployDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"deploy claim must NOT grant VisibilityFull — only 'admin' claim or is_org_admin does")
	})

	t.Run("contract with no grants still Redacted", func(t *testing.T) {
		orgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgID, "edge-nogrant-"+orgID[:8], "No Grant Org")
		require.NoError(t, err)

		contractAddr := "0xee01000000000000000000000000000000000001"
		contractID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'No Grant Contract')",
			contractID, orgID, contractAddr)
		require.NoError(t, err)

		// No groups, no contract_grants — just a bare contract

		// Anonymous viewer
		visMap, err := database.GetBatchVisibility(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"org contract with no grants must still be Redacted for anonymous viewer")

		// Authenticated but unrelated viewer
		visMap, err = database.GetBatchVisibility(ctx, "did:test:unrelated_viewer", []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"org contract with no grants must still be Redacted for authenticated viewer")
	})

	t.Run("user EOA: anonymous sees Hidden", func(t *testing.T) {
		eoaAddr := "0xff01000000000000000000000000000000000001"
		eoaDID := "did:test:eoa_owner"

		// Create user and link ETH address
		userID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
			userID, eoaDID)
		require.NoError(t, err)

		err = database.SystemLinkEthAddress(ctx, eoaDID, eoaAddr)
		require.NoError(t, err)

		// Anonymous viewer
		visMap, err := database.GetBatchVisibility(ctx, "", []string{eoaAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[eoaAddr],
			"anonymous must see owned EOA as Hidden (not Redacted, not Full)")
	})

	t.Run("user views own EOA as Full", func(t *testing.T) {
		eoaAddr := "0xff02000000000000000000000000000000000001"
		eoaDID := "did:test:own_eoa_viewer"

		userID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
			userID, eoaDID)
		require.NoError(t, err)

		err = database.SystemLinkEthAddress(ctx, eoaDID, eoaAddr)
		require.NoError(t, err)

		visMap, err := database.GetBatchVisibility(ctx, eoaDID, []string{eoaAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[eoaAddr],
			"user must see their own EOA as Full (ownerDID == viewerDID)")
	})

	t.Run("address case insensitivity", func(t *testing.T) {
		orgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgID, "edge-case-"+orgID[:8], "Case Org")
		require.NoError(t, err)

		// Store contract with mixed-case address
		mixedCaseAddr := "0xAAAA000000000000000000000000000000000099"
		contractID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Case Contract')",
			contractID, orgID, mixedCaseAddr)
		require.NoError(t, err)

		// Query with lowercase
		lowercaseAddr := "0xaaaa000000000000000000000000000000000099"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{lowercaseAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[lowercaseAddr],
			"org contract must be found despite case mismatch between stored and queried address")
	})

	t.Run("multi-org batch: admin sees own org Full, other Redacted", func(t *testing.T) {
		// Org X: admin group + contract
		orgXID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgXID, "edge-orgX-"+orgXID[:8], "Edge Org X")
		require.NoError(t, err)

		adminGroupX := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
			adminGroupX, orgXID)
		require.NoError(t, err)

		contractXAddr := "0xcc01000000000000000000000000000000000001"
		contractXID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract X')",
			contractXID, orgXID, contractXAddr)
		require.NoError(t, err)

		// Org Y: regular group + contract (user is NOT a member)
		orgYID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgYID, "edge-orgY-"+orgYID[:8], "Edge Org Y")
		require.NoError(t, err)

		regularGroupY := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'members', 'Members', 0, 'members', false)",
			regularGroupY, orgYID)
		require.NoError(t, err)

		contractYAddr := "0xcc02000000000000000000000000000000000001"
		contractYID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract Y')",
			contractYID, orgYID, contractYAddr)
		require.NoError(t, err)

		_, err = conn.ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
			uuid.New().String(), contractYID, regularGroupY)
		require.NoError(t, err)

		// User is admin of Org X only
		const multiOrgDID = "did:test:multi_org_admin"
		addMember(t, database, multiOrgDID, adminGroupX)

		// Single batch call with both contracts
		visMap, err := database.GetBatchVisibility(ctx, multiOrgDID, []string{contractXAddr, contractYAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractXAddr],
			"admin must see own org contract as Full in mixed batch")
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractYAddr],
			"admin must see other org contract as Redacted in mixed batch")
	})
}

// ============================================================================
// ViewerHasContractAccess
// ============================================================================

func TestViewerHasContractAccess(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	const contractAddr = "0xbbbb000000000000000000000000000000000001"
	contractID, groupID := setupOrgContract(t, database, contractAddr)

	ctx := context.Background()

	t.Run("member has access", func(t *testing.T) {
		const memberDID = "did:privado:has_access_member"
		addMember(t, database, memberDID, groupID)

		ok, err := database.ViewerHasContractAccess(ctx, memberDID, contractID)
		require.NoError(t, err)
		assert.True(t, ok, "group member must have contract access")
	})

	t.Run("non-member has no access", func(t *testing.T) {
		ok, err := database.ViewerHasContractAccess(ctx, "did:privado:no_access_outsider", contractID)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("empty DID has no access", func(t *testing.T) {
		ok, err := database.ViewerHasContractAccess(ctx, "", contractID)
		require.NoError(t, err)
		assert.False(t, ok, "empty DID must not match any user")
	})

	t.Run("expired membership has no access", func(t *testing.T) {
		const expiredDID = "did:privado:expired_contract_access"
		addExpiredMember(t, database, expiredDID, groupID)

		ok, err := database.ViewerHasContractAccess(ctx, expiredDID, contractID)
		require.NoError(t, err)
		assert.False(t, ok, "expired membership must not grant access")
	})

	t.Run("wrong contract ID has no access", func(t *testing.T) {
		const memberDID = "did:privado:wrong_contract_member"
		addMember(t, database, memberDID, groupID)

		ok, err := database.ViewerHasContractAccess(ctx, memberDID, uuid.New().String())
		require.NoError(t, err)
		assert.False(t, ok, "member of one contract must not access a different contract")
	})
}
