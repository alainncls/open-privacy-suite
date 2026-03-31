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

	t.Run("standard member with grant sees Full", func(t *testing.T) {
		const memberDID = "did:privado:batch_member"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"standard group member with contract_grant must have VisibilityFull — "+
				"aligns explorer visibility with RPC access")
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

	t.Run("unregistered address is Hidden (private by default)", func(t *testing.T) {
		const unregAddr = "0x9999000000000000000000000000000000000001"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{unregAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[unregAddr],
			"unregistered address (not in contracts table) must be VisibilityHidden (private by default)")
	})

	t.Run("precompile address is Full", func(t *testing.T) {
		const precompileAddr = "0x0000000000000000000000000000000000000001"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{precompileAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[precompileAddr],
			"precompile address must remain VisibilityFull")
	})

	t.Run("mixed batch: unregistered and private", func(t *testing.T) {
		const unregAddr = "0x9999000000000000000000000000000000000002"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{privateAddr, unregAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr])
		assert.Equal(t, explorer.VisibilityHidden, visMap[unregAddr],
			"unregistered address must be VisibilityHidden (private by default)")
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

	t.Run("read-only member with grant sees Full", func(t *testing.T) {
		memberDID := "did:test:reader_no_admin"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group with contract_grant sees Full regardless of claims — "+
				"aligns explorer visibility with RPC access")
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

	t.Run("deploy grant holder sees Full", func(t *testing.T) {
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
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"any grant holder sees Full — explorer visibility aligns with RPC access")
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
// G11: group_access.claims admin should grant VisibilityFull
// ============================================================================

// TestGetBatchVisibility_GroupAccessAdminClaim verifies that a group with
// 'admin' in group_access.claims AND a contract_grant on the contract receives
// VisibilityFull. This is the G11 fix — previously only is_org_admin and
// contract_grants.claims were checked, not group_access.claims.
func TestGetBatchVisibility_GroupAccessAdminClaim(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	// Setup: org + contract + non-admin group with contract_grant
	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "g11-org-"+orgID[:8], "G11 Test Org")
	require.NoError(t, err)

	contractAddr := "0xg110000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'G11 Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Group with group_access.claims = ['admin'] (NOT is_org_admin)
	adminClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admin-claim', 'Admin Claim Group', 0, 'admin-claim', false)",
		adminClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{admin}')",
		uuid.New().String(), adminClaimGroupID)
	require.NoError(t, err)

	// contract_grant linking the group to the contract (no claims on the grant itself)
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, adminClaimGroupID)
	require.NoError(t, err)

	// Group with group_access.claims = ['read'] and a contract_grant
	readClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'read-claim', 'Read Claim Group', 0, 'read-claim', false)",
		readClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{read}')",
		uuid.New().String(), readClaimGroupID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, readClaimGroupID)
	require.NoError(t, err)

	// Group with group_access.claims = ['admin'] but NO contract_grant
	noGrantGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admin-no-grant', 'Admin No Grant', 0, 'admin-no-grant', false)",
		noGrantGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{admin}')",
		uuid.New().String(), noGrantGroupID)
	require.NoError(t, err)
	// No contract_grant for this group

	t.Run("group_access admin claim + grant = VisibilityFull", func(t *testing.T) {
		const memberDID = "did:test:g11_admin_claim_member"
		addMember(t, database, memberDID, adminClaimGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group with 'admin' in group_access.claims + contract_grant must get VisibilityFull (G11 fix)")
	})

	t.Run("group_access read claim + grant = VisibilityFull", func(t *testing.T) {
		const memberDID = "did:test:g11_read_claim_member"
		addMember(t, database, memberDID, readClaimGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group with contract_grant sees Full regardless of claims — "+
				"explorer visibility aligns with RPC access")
	})

	t.Run("group_access admin claim but no grant = VisibilityRedacted", func(t *testing.T) {
		const memberDID = "did:test:g11_admin_no_grant_member"
		addMember(t, database, memberDID, noGrantGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"member of group with 'admin' in group_access.claims but NO contract_grant must NOT get VisibilityFull")
	})

	t.Run("is_org_admin still works", func(t *testing.T) {
		const adminDID = "did:test:g11_org_admin_member"

		orgAdminGroupID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'org-admins', 'Org Admins', 0, 'org-admins', true)",
			orgAdminGroupID, orgID)
		require.NoError(t, err)

		addMember(t, database, adminDID, orgAdminGroupID)

		visMap, err := database.GetBatchVisibility(ctx, adminDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"is_org_admin group member must still get VisibilityFull (existing behavior preserved)")
	})
}

// TestGetBatchVisibility_NoGrantNoFull verifies that users in a group WITHOUT
// a contract_grant on the specific contract still see Redacted. The grant-holder
// visibility upgrade must not leak to non-grant groups in the same org.
func TestGetBatchVisibility_NoGrantNoFull(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "nogrant-org-"+orgID[:8], "No Grant Org")
	require.NoError(t, err)

	contractAddr := "0xng01000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'No Grant Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Group A: has a contract_grant on this contract
	grantedGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'granted', 'Granted Group', 0, 'granted', false)",
		grantedGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{read}')",
		uuid.New().String(), contractID, grantedGroupID)
	require.NoError(t, err)

	// Group B: same org, NO contract_grant on this contract
	noGrantGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'no-grant', 'No Grant Group', 0, 'no-grant', false)",
		noGrantGroupID, orgID)
	require.NoError(t, err)

	t.Run("member of granted group sees Full", func(t *testing.T) {
		const memberDID = "did:test:nogrant_granted_member"
		addMember(t, database, memberDID, grantedGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group WITH contract_grant must see Full")
	})

	t.Run("member of non-granted group in same org sees Redacted", func(t *testing.T) {
		const memberDID = "did:test:nogrant_no_grant_member"
		addMember(t, database, memberDID, noGrantGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"member of group WITHOUT contract_grant must see Redacted — "+
				"being in the same org is not enough without a grant")
	})

	t.Run("member of different org sees Redacted", func(t *testing.T) {
		// Create a separate org with a group
		otherOrgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			otherOrgID, "other-org-"+otherOrgID[:8], "Other Org")
		require.NoError(t, err)

		otherGroupID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'members', 'Members', 0, 'members', false)",
			otherGroupID, otherOrgID)
		require.NoError(t, err)

		const memberDID = "did:test:nogrant_other_org_member"
		addMember(t, database, memberDID, otherGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"member of a different org must see Redacted — cross-org isolation")
	})
}

// TestGetBatchVisibilityDetailed_GroupAccessAdminClaim verifies the same G11
// fix applies to GetBatchVisibilityDetailed.
func TestGetBatchVisibilityDetailed_GroupAccessAdminClaim(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "g11d-org-"+orgID[:8], "G11 Detailed Test Org")
	require.NoError(t, err)

	contractAddr := "0xg11d000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'G11D Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Group with group_access.claims = ['admin'] + contract_grant
	adminClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admin-claim-d', 'Admin Claim Detailed', 0, 'admin-claim-d', false)",
		adminClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{admin}')",
		uuid.New().String(), adminClaimGroupID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, adminClaimGroupID)
	require.NoError(t, err)

	// Group with group_access.claims = ['read'] + contract_grant
	readClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'read-claim-d', 'Read Claim Detailed', 0, 'read-claim-d', false)",
		readClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{read}')",
		uuid.New().String(), readClaimGroupID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, readClaimGroupID)
	require.NoError(t, err)

	t.Run("group_access admin claim + grant = VisibilityFull", func(t *testing.T) {
		const memberDID = "did:test:g11d_admin_claim_member"
		addMember(t, database, memberDID, adminClaimGroupID)

		visMap, err := database.GetBatchVisibilityDetailed(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		vis := visMap[contractAddr]
		assert.Equal(t, explorer.VisibilityFull, vis.Level,
			"member of group with 'admin' in group_access.claims + contract_grant must get VisibilityFull (G11 fix)")
		assert.True(t, vis.Visible)
		assert.Equal(t, explorer.ReasonRBACGroupMember, vis.Reason)
	})

	t.Run("group_access read claim + grant = VisibilityFull (Detailed gives Full to any grant holder)", func(t *testing.T) {
		const memberDID = "did:test:g11d_read_claim_member"
		addMember(t, database, memberDID, readClaimGroupID)

		visMap, err := database.GetBatchVisibilityDetailed(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		vis := visMap[contractAddr]
		// GetBatchVisibilityDetailed (privacy dashboard) gives Full to
		// any grant holder regardless of claims. This differs from GetBatchVisibility
		// (redaction engine) which only gives Full to admins.
		assert.Equal(t, explorer.VisibilityFull, vis.Level,
			"Detailed: any grant holder sees Full (for privacy dashboard)")
		assert.True(t, vis.Visible)
	})

	t.Run("anonymous sees Redacted", func(t *testing.T) {
		visMap, err := database.GetBatchVisibilityDetailed(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		vis := visMap[contractAddr]
		assert.Equal(t, explorer.VisibilityRedacted, vis.Level,
			"anonymous viewer must see org contract as Redacted")
		assert.False(t, vis.Visible)
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
