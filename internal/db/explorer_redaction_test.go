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

	t.Run("member sees Full", func(t *testing.T) {
		const memberDID = "did:privado:batch_member"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"group member must have VisibilityFull for their org contract")
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
