package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupLogVisibilityDB(t *testing.T) *DB {
	t.Helper()
	database := setupTestDB(t)
	t.Cleanup(func() { cleanupTestDB(t, database) })
	return database
}

func TestSaveAndGetTxLogVisibility(t *testing.T) {
	database := setupLogVisibilityDB(t)
	ctx := context.Background()

	t.Run("roundtrip save and get", func(t *testing.T) {
		txHash := "0xdeadbeef0000000000000000000000000000000000000000000000000000cafe"
		dids := []string{"did:privado:user1", "did:privado:user2"}
		senderDID := "did:privado:sender"
		orgID := "org-1"

		err := database.SaveTxLogVisibility(ctx, txHash, dids, senderDID, orgID)
		require.NoError(t, err)

		got, err := database.GetTxLogVisibility(ctx, txHash)
		require.NoError(t, err)
		assert.ElementsMatch(t, dids, got)
	})

	t.Run("get nonexistent tx returns nil", func(t *testing.T) {
		got, err := database.GetTxLogVisibility(ctx, "0xnonexistent")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("save with empty dids is no-op", func(t *testing.T) {
		err := database.SaveTxLogVisibility(ctx, "0xempty", nil, "did:sender", "org-1")
		require.NoError(t, err)

		got, err := database.GetTxLogVisibility(ctx, "0xempty")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("save with empty hash is no-op", func(t *testing.T) {
		err := database.SaveTxLogVisibility(ctx, "", []string{"did:user"}, "did:sender", "org-1")
		require.NoError(t, err)
	})

	t.Run("hash is normalized to lowercase", func(t *testing.T) {
		txHash := "0xABCDEF0000000000000000000000000000000000000000000000000000001234"
		dids := []string{"did:privado:case_user"}

		err := database.SaveTxLogVisibility(ctx, txHash, dids, "did:sender", "org-1")
		require.NoError(t, err)

		// Query with lowercase
		got, err := database.GetTxLogVisibility(ctx, "0xabcdef0000000000000000000000000000000000000000000000000000001234")
		require.NoError(t, err)
		assert.Equal(t, dids, got)
	})
}

func TestGetBatchTxLogVisibility(t *testing.T) {
	database := setupLogVisibilityDB(t)
	ctx := context.Background()

	tx1 := "0x1111111111111111111111111111111111111111111111111111111111111111"
	tx2 := "0x2222222222222222222222222222222222222222222222222222222222222222"
	tx3 := "0x3333333333333333333333333333333333333333333333333333333333333333"

	require.NoError(t, database.SaveTxLogVisibility(ctx, tx1, []string{"did:a"}, "did:sender", "org-1"))
	require.NoError(t, database.SaveTxLogVisibility(ctx, tx2, []string{"did:b", "did:c"}, "did:sender", "org-1"))

	t.Run("batch returns all found hashes", func(t *testing.T) {
		got, err := database.GetBatchTxLogVisibility(ctx, []string{tx1, tx2, tx3})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, []string{"did:a"}, got[tx1])
		assert.ElementsMatch(t, []string{"did:b", "did:c"}, got[tx2])
		_, exists := got[tx3]
		assert.False(t, exists, "tx3 should not be in result")
	})

	t.Run("batch with empty input returns nil", func(t *testing.T) {
		got, err := database.GetBatchTxLogVisibility(ctx, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}
