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

func TestGetSharedLogsForDID(t *testing.T) {
	database := setupLogVisibilityDB(t)
	ctx := context.Background()

	viewerDID := "did:privado:viewer"
	otherDID := "did:privado:other"

	tx1 := "0xaaaa111111111111111111111111111111111111111111111111111111111111"
	tx2 := "0xaaaa222222222222222222222222222222222222222222222222222222222222"
	tx3 := "0xaaaa333333333333333333333333333333333333333333333333333333333333"

	// Save visibility entries: tx1 and tx2 visible to viewerDID, tx3 only to otherDID.
	require.NoError(t, database.SaveTxLogVisibility(ctx, tx1, []string{viewerDID, otherDID}, "did:sender1", "org-1"))
	require.NoError(t, database.SaveTxLogVisibility(ctx, tx2, []string{viewerDID}, "did:sender2", "org-2"))
	require.NoError(t, database.SaveTxLogVisibility(ctx, tx3, []string{otherDID}, "did:sender3", "org-1"))

	t.Run("returns entries for viewer", func(t *testing.T) {
		entries, total, err := database.GetSharedLogsForDID(ctx, viewerDID, 20, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		require.Len(t, entries, 2)

		// Ordered by created_at DESC — tx2 was inserted after tx1.
		assert.Equal(t, tx2, entries[0].TxHash)
		assert.Equal(t, "did:sender2", entries[0].SenderDID)
		assert.Equal(t, "org-2", entries[0].OrgID)
		assert.NotEmpty(t, entries[0].CreatedAt)

		assert.Equal(t, tx1, entries[1].TxHash)
		assert.Equal(t, "did:sender1", entries[1].SenderDID)
	})

	t.Run("returns entries for other viewer", func(t *testing.T) {
		entries, total, err := database.GetSharedLogsForDID(ctx, otherDID, 20, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, total) // tx1 and tx3
		require.Len(t, entries, 2)
	})

	t.Run("non-viewer gets empty result", func(t *testing.T) {
		entries, total, err := database.GetSharedLogsForDID(ctx, "did:privado:nobody", 20, 0)
		require.NoError(t, err)
		assert.Equal(t, 0, total)
		assert.Nil(t, entries)
	})

	t.Run("empty DID returns nil", func(t *testing.T) {
		entries, total, err := database.GetSharedLogsForDID(ctx, "", 20, 0)
		require.NoError(t, err)
		assert.Equal(t, 0, total)
		assert.Nil(t, entries)
	})

	t.Run("pagination works", func(t *testing.T) {
		// Limit 1 — should return only the most recent entry.
		entries, total, err := database.GetSharedLogsForDID(ctx, viewerDID, 1, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, total) // total is still 2
		require.Len(t, entries, 1)
		assert.Equal(t, tx2, entries[0].TxHash)

		// Offset 1, limit 1 — should return the second entry.
		entries, total, err = database.GetSharedLogsForDID(ctx, viewerDID, 1, 1)
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		require.Len(t, entries, 1)
		assert.Equal(t, tx1, entries[0].TxHash)

		// Offset beyond total — empty.
		entries, total, err = database.GetSharedLogsForDID(ctx, viewerDID, 20, 10)
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Empty(t, entries)
	})
}
