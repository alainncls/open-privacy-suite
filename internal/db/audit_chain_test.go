package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// computeChainHash mirrors internal/audit.HashChain.ComputeNext but is duplicated
// here to keep the test free of cross-package coupling. The value MUST stay in
// lockstep with hashchain.go.
func computeChainHash(prev, content string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// seedAccessLogs inserts n access_logs rows for a single user, computing and
// persisting the entry_hash chain forward. Returns the ids and hashes in
// insertion order.
func seedAccessLogs(t *testing.T, ctx context.Context, d *DB, n int, prev string) ([]int64, []string) {
	t.Helper()
	ids := make([]int64, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id, createdAt, err := d.LogAccessEnhanced(ctx, "did:test:user", "eth_call", 200, "127.0.0.1", "", nil, nil)
		if err != nil {
			t.Fatalf("seed insert %d: %v", i, err)
		}
		// Mirror jsonrpc_processor.go entry content layout.
		content := fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
			id, "did:test:user", "eth_call", "127.0.0.1", 200, 200,
			createdAt.Format(time.RFC3339Nano), "", "")
		hash := computeChainHash(prev, content)
		if err := d.UpdateAccessLogHash(ctx, id, hash); err != nil {
			t.Fatalf("update hash %d: %v", id, err)
		}
		prev = hash
		ids = append(ids, id)
		hashes = append(hashes, hash)
	}
	return ids, hashes
}

// TestFIFOTrim_AnchorFlow drives a real Postgres through the FIFO trim path
// and verifies (a) the row count drops to the cap, (b) the audit_chain_anchor
// table records the (id, hash) of the highest deleted row, (c) walking the
// surviving rows from the anchor as seed reproduces every row's entry_hash —
// i.e. the hash chain is verifiable across the cut.
func TestFIFOTrim_AnchorFlow(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	const totalRows = 12
	const maxRows = 5

	ids, hashes := seedAccessLogs(t, ctx, database, totalRows, "")

	// Trim down to maxRows; loop until 0 deleted.
	var totalDeleted int64
	for i := 0; i < 100; i++ {
		deleted, err := database.TrimAccessLogsFIFOBatch(ctx, maxRows, 1000)
		if err != nil {
			t.Fatalf("trim batch: %v", err)
		}
		if deleted == 0 {
			break
		}
		totalDeleted += deleted
	}
	if totalDeleted != int64(totalRows-maxRows) {
		t.Fatalf("expected %d rows deleted, got %d", totalRows-maxRows, totalDeleted)
	}

	// Surviving row count.
	count, err := database.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != int64(maxRows) {
		t.Fatalf("expected %d surviving rows, got %d", maxRows, count)
	}

	// The anchor row should pin the highest deleted id and its entry_hash.
	anchor, err := database.GetAuditChainAnchor(ctx, ChainNameAccessLogs)
	if err != nil {
		t.Fatalf("get anchor: %v", err)
	}
	if anchor == nil {
		t.Fatal("expected anchor row, got nil")
	}
	expectedAnchorID := ids[totalRows-maxRows-1]
	expectedAnchorHash := hashes[totalRows-maxRows-1]
	if anchor.LastPrunedID != expectedAnchorID {
		t.Fatalf("anchor id mismatch: want %d, got %d", expectedAnchorID, anchor.LastPrunedID)
	}
	if anchor.LastPrunedEntryHash != expectedAnchorHash {
		t.Fatalf("anchor hash mismatch: want %s, got %s", expectedAnchorHash, anchor.LastPrunedEntryHash)
	}

	// The seeder used for a fresh chain on startup must return the anchor
	// hash now that the originally-seeded rows are still in the DB. (Surviving
	// rows have entry_hash set so the function should still prefer the most
	// recent surviving hash. Verify this matches the last surviving entry.)
	seed, err := database.GetLatestAccessLogHash(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seed != hashes[totalRows-1] {
		t.Fatalf("seed should reflect newest surviving row %s, got %s", hashes[totalRows-1], seed)
	}

	// Hash-chain forward walk: seed = anchor hash, then recompute entry_hash
	// for each surviving row and confirm it matches what the DB stored.
	rows, err := database.Conn().QueryContext(ctx, `
		SELECT id, external_id, method, status_code, response_status, ip_address,
		       correlation_id, request_params, entry_hash, hash_format_version, created_at
		FROM access_logs ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("select surviving: %v", err)
	}
	defer rows.Close()

	prev := anchor.LastPrunedEntryHash
	walked := 0
	for rows.Next() {
		var l AccessLog
		var corrID sql.NullString
		var entryHash sql.NullString
		var respStatus *int
		var params []byte
		var createdAtStr string
		if err := rows.Scan(&l.ID, &l.ExternalID, &l.Method, &l.StatusCode, &respStatus, &l.IPAddress, &corrID, &params, &entryHash, &l.HashFormatVersion, &createdAtStr); err != nil {
			t.Fatalf("scan: %v", err)
		}
		// We seeded with no correlation id and no params, status 200/200 — the
		// content string the processor would have built is reproducible here.
		createdAt, perr := time.Parse(time.RFC3339Nano, createdAtStr)
		if perr != nil {
			// Fallback: the driver may return stripped-precision RFC3339.
			createdAt, perr = time.Parse(time.RFC3339, createdAtStr)
			if perr != nil {
				t.Fatalf("parse created_at %q: %v", createdAtStr, perr)
			}
		}
		content := fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
			l.ID, "did:test:user", "eth_call", "127.0.0.1", 200, 200,
			createdAt.Format(time.RFC3339Nano), "", "")
		got := computeChainHash(prev, content)
		if got != entryHash.String {
			t.Fatalf("hash mismatch on id=%d: want %s, got %s", l.ID, entryHash.String, got)
		}
		prev = got
		walked++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if walked != maxRows {
		t.Fatalf("walked %d rows, expected %d", walked, maxRows)
	}
}

// TestTimeBasedPrune_WritesAnchor verifies that the existing CleanupAccessLogs
// path also persists the anchor — Option A: TTL prune must keep the chain
// verifiable across the cut.
func TestTimeBasedPrune_WritesAnchor(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	ids, hashes := seedAccessLogs(t, ctx, database, 5, "")

	// Backdate the first 3 rows so they fall outside the retention window.
	cutoff := time.Now().Add(-1 * time.Hour)
	if _, err := database.Conn().ExecContext(ctx,
		`UPDATE access_logs SET created_at = $1 WHERE id <= $2`, cutoff.Add(-time.Minute), ids[2]); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	deleted, err := database.CleanupAccessLogs(ctx, cutoff)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("expected 3 rows deleted, got %d", deleted)
	}

	anchor, err := database.GetAuditChainAnchor(ctx, ChainNameAccessLogs)
	if err != nil {
		t.Fatalf("get anchor: %v", err)
	}
	if anchor == nil {
		t.Fatal("expected anchor after time-based prune, got nil")
	}
	if anchor.LastPrunedID != ids[2] {
		t.Fatalf("anchor id: want %d, got %d", ids[2], anchor.LastPrunedID)
	}
	if anchor.LastPrunedEntryHash != hashes[2] {
		t.Fatalf("anchor hash: want %s, got %s", hashes[2], anchor.LastPrunedEntryHash)
	}
}

// TestGetLatestAccessLogHash_FallsBackToAnchor confirms that the chain seeder
// reads from the anchor when no surviving access_logs row carries a hash.
func TestGetLatestAccessLogHash_FallsBackToAnchor(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	// Seed and trim everything: the surviving table is empty but the anchor
	// must still hold the last-known hash.
	_, hashes := seedAccessLogs(t, ctx, database, 4, "")
	for i := 0; i < 10; i++ {
		deleted, err := database.TrimAccessLogsFIFOBatch(ctx, 0, 1000)
		if err != nil {
			t.Fatalf("trim: %v", err)
		}
		if deleted == 0 {
			break
		}
	}
	count, err := database.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 surviving, got %d", count)
	}

	seed, err := database.GetLatestAccessLogHash(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seed == "" {
		t.Fatal("seed should fall back to anchor, got empty string")
	}
	if seed != hashes[len(hashes)-1] {
		t.Fatalf("seed should equal last hash before prune: want %s, got %s", hashes[len(hashes)-1], seed)
	}
}
