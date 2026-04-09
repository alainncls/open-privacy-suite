package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// SaveTxLogVisibility stores logVisibleTo DIDs for a transaction.
// Must be called BEFORE forwarding the tx to the node (race condition prevention:
// the rule must be in the DB before anyone can query the receipt).
func (d *DB) SaveTxLogVisibility(ctx context.Context, txHash string, visibleToDIDs []string, senderDID, orgID string) error {
	if txHash == "" || len(visibleToDIDs) == 0 {
		return nil
	}
	query := `INSERT INTO tx_log_visible_to (tx_hash, visible_to_dids, sender_did, org_id)
	          VALUES ($1, $2, $3, $4)`
	_, err := d.conn.ExecContext(ctx, query, strings.ToLower(txHash), pq.Array(visibleToDIDs), senderDID, orgID)
	if err != nil {
		return fmt.Errorf("failed to save tx log visibility: %w", err)
	}
	return nil
}

// GetTxLogVisibility returns the visible_to_dids for a single tx hash.
// Returns nil (not an error) if no logVisibleTo rule exists for the tx.
func (d *DB) GetTxLogVisibility(ctx context.Context, txHash string) ([]string, error) {
	query := `SELECT visible_to_dids FROM tx_log_visible_to WHERE tx_hash = $1 LIMIT 1`
	var dids []string
	err := d.conn.QueryRowContext(ctx, query, strings.ToLower(txHash)).Scan(pq.Array(&dids))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tx log visibility: %w", err)
	}
	return dids, nil
}

// GetBatchTxLogVisibility returns visible_to_dids for multiple tx hashes in a
// single query. Returns map[txHash][]string. Hashes not found are absent from
// the map (not an error).
func (d *DB) GetBatchTxLogVisibility(ctx context.Context, txHashes []string) (map[string][]string, error) {
	if len(txHashes) == 0 {
		return nil, nil
	}

	// Normalize to lowercase.
	lower := make([]string, len(txHashes))
	for i, h := range txHashes {
		lower[i] = strings.ToLower(h)
	}

	query := `SELECT tx_hash, visible_to_dids FROM tx_log_visible_to WHERE tx_hash = ANY($1)`
	rows, err := d.conn.QueryContext(ctx, query, pq.Array(lower))
	if err != nil {
		return nil, fmt.Errorf("failed to batch get tx log visibility: %w", err)
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var txHash string
		var dids []string
		if err := rows.Scan(&txHash, pq.Array(&dids)); err != nil {
			return nil, fmt.Errorf("failed to scan tx log visibility row: %w", err)
		}
		result[txHash] = dids
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tx log visibility rows: %w", err)
	}
	return result, nil
}

// SharedLogEntry represents a transaction whose logs are shared with a viewer via logVisibleTo.
type SharedLogEntry struct {
	TxHash    string
	SenderDID string
	OrgID     string
	CreatedAt string // RFC3339 timestamp
}

// GetSharedLogsForDID returns tx hashes where the given DID appears in visible_to_dids,
// ordered by created_at descending, with pagination.
// Returns the entries, total count, and any error.
func (d *DB) GetSharedLogsForDID(ctx context.Context, viewerDID string, limit, offset int) ([]SharedLogEntry, int, error) {
	if viewerDID == "" {
		return nil, 0, nil
	}

	// Count total matching rows.
	var total int
	countQuery := `SELECT COUNT(*) FROM tx_log_visible_to WHERE $1 = ANY(visible_to_dids)`
	if err := d.conn.QueryRowContext(ctx, countQuery, viewerDID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count shared logs: %w", err)
	}
	if total == 0 {
		return nil, 0, nil
	}

	query := `SELECT tx_hash, sender_did, org_id, created_at
	           FROM tx_log_visible_to
	           WHERE $1 = ANY(visible_to_dids)
	           ORDER BY created_at DESC
	           LIMIT $2 OFFSET $3`
	rows, err := d.conn.QueryContext(ctx, query, viewerDID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query shared logs: %w", err)
	}
	defer rows.Close()

	var entries []SharedLogEntry
	for rows.Next() {
		var e SharedLogEntry
		var createdAt sql.NullTime
		if err := rows.Scan(&e.TxHash, &e.SenderDID, &e.OrgID, &createdAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan shared log entry: %w", err)
		}
		if createdAt.Valid {
			e.CreatedAt = createdAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate shared log entries: %w", err)
	}

	return entries, total, nil
}
