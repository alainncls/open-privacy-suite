package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/tern/v2/migrate"

	"privacy-proxy/internal/db/migrations"
)

const (
	// dbMaxRetries is the number of connection attempts before giving up.
	dbMaxRetries = 15
	// dbRetryInterval is the delay between connection attempts.
	dbRetryInterval = 2 * time.Second
)

// ErrAddressLinkRevoked is returned when an ETH address link was revoked by an administrator
// and the user attempts to re-link it. Requires explicit admin action to un-revoke.
var ErrAddressLinkRevoked = errors.New("ETH address link has been revoked by an administrator")

// ErrNotFound is returned when the requested resource does not exist.
var ErrNotFound = errors.New("not found")

// ErrRecordAlreadyUsed is returned when attempting to delete a travel rule record that has already been used.
var ErrRecordAlreadyUsed = errors.New("travel rule record already used")

type DB struct {
	conn        *sql.DB
	databaseURL string
}

// Conn returns the underlying database connection (for testing)
func (d *DB) Conn() *sql.DB {
	return d.conn
}

func New(databaseURL string) (*DB, error) {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(50)
	conn.SetMaxIdleConns(25)
	conn.SetConnMaxLifetime(5 * time.Minute)

	// Retry initial connection — Postgres may not be ready at startup
	// (e.g. external database still booting, or built-in Postgres starting in parallel).
	ctx := context.Background()
	var lastErr error
	for attempt := 1; attempt <= dbMaxRetries; attempt++ {
		if err := conn.PingContext(ctx); err != nil {
			lastErr = err
			if attempt < dbMaxRetries {
				slog.Warn("postgres not ready, retrying",
					"attempt", attempt,
					"max", dbMaxRetries,
					"next_retry_in", dbRetryInterval,
					"error", err)
				time.Sleep(dbRetryInterval)
			}
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		conn.Close()
		return nil, fmt.Errorf("postgres connection failed after %d attempts: %w", dbMaxRetries, lastErr)
	}

	db := &DB{conn: conn, databaseURL: databaseURL}

	if err := db.Migrate(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

// NewWithoutMigrate creates a database connection without running migrations.
// Use this when you need to check migration status or run migrations manually.
func NewWithoutMigrate(databaseURL string) (*DB, error) {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(50)
	conn.SetMaxIdleConns(25)
	conn.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	ctx := context.Background()
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{conn: conn, databaseURL: databaseURL}, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

// Migrate runs all pending database migrations using tern.
func (d *DB) Migrate(ctx context.Context) error {
	pgxConn, err := pgx.Connect(ctx, d.databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect for migrations: %w", err)
	}
	defer pgxConn.Close(ctx)

	migrator, err := migrate.NewMigrator(ctx, pgxConn, "schema_version")
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	if err := migrator.LoadMigrations(migrations.FS); err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

// MigrateWithProgress runs migrations with a progress callback for CLI usage.
// The callback receives: sequence number, migration name, direction ("up"/"down"), and SQL.
func (d *DB) MigrateWithProgress(ctx context.Context, onStart func(sequence int32, name, direction, sql string)) error {
	pgxConn, err := pgx.Connect(ctx, d.databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect for migrations: %w", err)
	}
	defer pgxConn.Close(ctx)

	migrator, err := migrate.NewMigrator(ctx, pgxConn, "schema_version")
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	if err := migrator.LoadMigrations(migrations.FS); err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if onStart != nil {
		migrator.OnStart = onStart
	}

	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

// GetMigrationStatus returns the current migration version and pending migrations.
func (d *DB) GetMigrationStatus(ctx context.Context) (currentVersion int32, pendingCount int, err error) {
	pgxConn, err := pgx.Connect(ctx, d.databaseURL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to connect for migrations: %w", err)
	}
	defer pgxConn.Close(ctx)

	migrator, err := migrate.NewMigrator(ctx, pgxConn, "schema_version")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create migrator: %w", err)
	}

	if err := migrator.LoadMigrations(migrations.FS); err != nil {
		return 0, 0, fmt.Errorf("failed to load migrations: %w", err)
	}

	version, err := migrator.GetCurrentVersion(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get current version: %w", err)
	}

	pending := len(migrator.Migrations) - int(version)
	if pending < 0 {
		pending = 0
	}

	return version, pending, nil
}

func (d *DB) LogAccess(ctx context.Context, externalID, method string, statusCode int, ipAddress string) error {
	query := `INSERT INTO access_logs (external_id, method, status_code, ip_address)
	          VALUES ($1, $2, $3, $4)`

	_, err := d.conn.ExecContext(ctx, query, externalID, method, statusCode, ipAddress)
	return err
}

type AccessLog struct {
	ID               int              `json:"id"`
	ExternalID       string           `json:"external_id"`
	Method           string           `json:"method"`
	StatusCode       int              `json:"status_code"`
	ResponseStatus   *int             `json:"response_status,omitempty"`
	IPAddress        string           `json:"ip_address"`
	CorrelationID    *string          `json:"correlation_id,omitempty"`
	RequestParams    *json.RawMessage `json:"request_params,omitempty"`
	EntryHash        *string          `json:"entry_hash,omitempty"`
	HashFormatVersion int             `json:"hash_format_version"`
	CreatedAt        string           `json:"created_at"`
}

// AccessLogFilter narrows GetAccessLogs / CountAccessLogs results. Every field
// is optional — zero values mean "no constraint on this field". Filters are
// always applied as parameterised SQL (no string concatenation of inputs).
type AccessLogFilter struct {
	ExternalID    string
	Method        string
	StatusCode    int    // 0 = unset
	CorrelationID string
	From          time.Time // zero = unset
	To            time.Time // zero = unset
	Limit         int       // <=0 = default 100; clamped to 1000
	Offset        int
}

// MaxAccessLogQueryLimit is the server-side cap on `limit` for the access-log
// admin endpoint. Limits above this are clamped down silently.
const MaxAccessLogQueryLimit = 1000

// buildAccessLogWhere returns the WHERE clause (without the leading "WHERE")
// and the positional args for the supplied filter. The first arg index is 1.
// Returns ("", nil) when no constraints apply.
func buildAccessLogWhere(f AccessLogFilter) (string, []any) {
	clauses := make([]string, 0, 6)
	args := make([]any, 0, 6)
	idx := 1

	if f.ExternalID != "" {
		clauses = append(clauses, fmt.Sprintf("external_id = $%d", idx))
		args = append(args, f.ExternalID)
		idx++
	}
	if f.Method != "" {
		clauses = append(clauses, fmt.Sprintf("method = $%d", idx))
		args = append(args, f.Method)
		idx++
	}
	if f.StatusCode != 0 {
		clauses = append(clauses, fmt.Sprintf("status_code = $%d", idx))
		args = append(args, f.StatusCode)
		idx++
	}
	if f.CorrelationID != "" {
		clauses = append(clauses, fmt.Sprintf("correlation_id = $%d", idx))
		args = append(args, f.CorrelationID)
		idx++
	}
	if !f.From.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, f.From)
		idx++
	}
	if !f.To.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, f.To)
		idx++
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return strings.Join(clauses, " AND "), args
}

// GetAccessLogs returns access log rows ordered by created_at DESC, applying
// the supplied filter. Limit is clamped to [1, MaxAccessLogQueryLimit].
func (d *DB) GetAccessLogs(ctx context.Context, f AccessLogFilter) ([]*AccessLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxAccessLogQueryLimit {
		limit = MaxAccessLogQueryLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := buildAccessLogWhere(f)
	query := `SELECT id, external_id, method, status_code, response_status, ip_address,
	          correlation_id, request_params, entry_hash, hash_format_version, created_at
	          FROM access_logs`
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*AccessLog, 0)

	for rows.Next() {
		var log AccessLog
		var correlationID, entryHash sql.NullString
		var responseStatus sql.NullInt32
		var requestParams []byte

		if err := rows.Scan(
			&log.ID,
			&log.ExternalID,
			&log.Method,
			&log.StatusCode,
			&responseStatus,
			&log.IPAddress,
			&correlationID,
			&requestParams,
			&entryHash,
			&log.HashFormatVersion,
			&log.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan log: %w", err)
		}

		if correlationID.Valid {
			log.CorrelationID = &correlationID.String
		}
		if responseStatus.Valid {
			rs := int(responseStatus.Int32)
			log.ResponseStatus = &rs
		}
		if len(requestParams) > 0 {
			raw := json.RawMessage(requestParams)
			log.RequestParams = &raw
		}
		if entryHash.Valid {
			log.EntryHash = &entryHash.String
		}

		logs = append(logs, &log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate logs: %w", err)
	}

	return logs, nil
}

// CountAccessLogs returns the number of access log rows matching the supplied
// filter (ignoring Limit/Offset). Used by the admin API to render pagination.
func (d *DB) CountAccessLogs(ctx context.Context, f AccessLogFilter) (int64, error) {
	where, args := buildAccessLogWhere(f)
	query := "SELECT COUNT(*) FROM access_logs"
	if where != "" {
		query += " WHERE " + where
	}
	var n int64
	if err := d.conn.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("failed to count access logs: %w", err)
	}
	return n, nil
}

// LogAccessEnhanced inserts an access log entry with correlation ID, optional request params, and returns the ID and created_at for hash chain computation.
// responseStatus is the HTTP status returned to the client (may differ from statusCode for opaque denials).
func (d *DB) LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte, responseStatus *int) (int64, time.Time, error) {
	query := `INSERT INTO access_logs (external_id, method, status_code, ip_address, correlation_id, request_params, response_status, hash_format_version)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, 2)
	          RETURNING id, created_at`

	var id int64
	var createdAt time.Time
	var corrID *string
	if correlationID != "" {
		corrID = &correlationID
	}

	err := d.conn.QueryRowContext(ctx, query, externalID, method, statusCode, ipAddress, corrID, params, responseStatus).Scan(&id, &createdAt)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to log enhanced access: %w", err)
	}
	return id, createdAt, nil
}

// UpdateAccessLogHash sets the entry_hash for an access log entry after hash chain computation.
func (d *DB) UpdateAccessLogHash(ctx context.Context, id int64, hash string) error {
	_, err := d.conn.ExecContext(ctx, `UPDATE access_logs SET entry_hash = $2 WHERE id = $1`, id, hash)
	return err
}

// GetLatestAccessLogHash returns the seed for the access_logs hash chain.
// Resolution order:
//  1. The entry_hash of the most recent surviving access_logs row.
//  2. If no surviving rows have an entry_hash, the last_pruned_entry_hash from
//     the audit_chain_anchor table for chain "access_logs". This keeps the
//     chain verifiable when retention has trimmed every previous row.
//  3. Otherwise the empty string (fresh chain).
func (d *DB) GetLatestAccessLogHash(ctx context.Context) (string, error) {
	var hash sql.NullString
	err := d.conn.QueryRowContext(ctx,
		`SELECT entry_hash FROM access_logs WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("failed to get latest access log hash: %w", err)
	}
	if hash.Valid && hash.String != "" {
		return hash.String, nil
	}
	// Fallback: anchor table preserves the seed across pruning cuts.
	anchor, err := d.GetAuditChainAnchor(ctx, ChainNameAccessLogs)
	if err != nil {
		return "", err
	}
	if anchor != nil {
		return anchor.LastPrunedEntryHash, nil
	}
	return "", nil
}

// CleanupAccessLogs deletes access log entries older than the given time AND
// updates the access_logs chain anchor with the (id, entry_hash) of the last
// row to be deleted in this batch. The anchor write + delete run inside a
// single transaction so the chain stays verifiable even if the prune is
// interrupted between rows.
//
// If no rows match the cutoff, the anchor is left unchanged. If the row about
// to be deleted has a NULL entry_hash (e.g. the row never received an
// UpdateAccessLogHash because the process crashed between insert and update),
// the anchor still records the row's id but uses the previous anchor hash —
// that is the latest known good seed for downstream verification.
func (d *DB) CleanupAccessLogs(ctx context.Context, olderThan time.Time) (PruneResult, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return PruneResult{}, fmt.Errorf("failed to begin cleanup transaction: %w", err)
	}
	defer func() {
		// Best-effort rollback if commit didn't happen.
		_ = tx.Rollback()
	}()

	// Pick the row with the lowest id among those about to be deleted —
	// surfaced via PruneResult.LowestID so the audit-of-the-audit row can
	// describe the full deleted range, not just its endpoint.
	var firstID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM access_logs
		WHERE created_at < $1
		ORDER BY id ASC
		LIMIT 1`, olderThan).Scan(&firstID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PruneResult{}, fmt.Errorf("failed to read prune lowest id for access_logs: %w", err)
	}

	// Pick the row with the highest id among those about to be deleted.
	var lastID sql.NullInt64
	var lastHash sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id, entry_hash FROM access_logs
		WHERE created_at < $1
		ORDER BY id DESC
		LIMIT 1`, olderThan).Scan(&lastID, &lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PruneResult{}, fmt.Errorf("failed to read prune cut for access_logs: %w", err)
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM access_logs WHERE created_at < $1`, olderThan)
	if err != nil {
		return PruneResult{}, fmt.Errorf("failed to cleanup access logs: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return PruneResult{}, fmt.Errorf("failed to count deleted access logs: %w", err)
	}

	res := PruneResult{Deleted: deleted}
	if deleted > 0 && lastID.Valid {
		anchorHash := lastHash.String
		if !lastHash.Valid || anchorHash == "" {
			// The row had no entry_hash — fall back to the previous anchor so
			// downstream verifiers still have a valid seed. If there is no
			// previous anchor either, write the empty string (chain restarts
			// from genesis).
			prev, perr := getAnchorHashTx(ctx, tx, ChainNameAccessLogs)
			if perr != nil {
				return PruneResult{}, perr
			}
			anchorHash = prev
		}
		if err := upsertAuditChainAnchorTx(ctx, tx, ChainNameAccessLogs, lastID.Int64, anchorHash); err != nil {
			return PruneResult{}, err
		}
		res.HighestID = lastID.Int64
		res.AnchorHash = anchorHash
		if firstID.Valid {
			res.LowestID = firstID.Int64
		}
	}

	if err := tx.Commit(); err != nil {
		return PruneResult{}, fmt.Errorf("failed to commit access log cleanup: %w", err)
	}
	return res, nil
}

// getAnchorHashTx is a tx-scoped helper that returns the last_pruned_entry_hash
// for chainName, or "" if no row exists.
func getAnchorHashTx(ctx context.Context, tx *sql.Tx, chainName string) (string, error) {
	var hash string
	err := tx.QueryRowContext(ctx,
		`SELECT last_pruned_entry_hash FROM audit_chain_anchor WHERE chain_name = $1`,
		chainName).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read existing anchor hash for %q: %w", chainName, err)
	}
	return hash, nil
}

// CountAccessLogsTotal returns the total number of access_logs rows.
// Used by the FIFO sweeper to decide whether to trim.
func (d *DB) CountAccessLogsTotal(ctx context.Context) (int64, error) {
	var n int64
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_logs`).Scan(&n); err != nil {
		return 0, fmt.Errorf("failed to count access_logs: %w", err)
	}
	return n, nil
}

// TrimAccessLogsFIFOBatch deletes the oldest rows from access_logs, capping
// the deletion at batchSize, until at most maxRows remain. It writes the
// chain anchor in the same transaction (highest id + its entry_hash among the
// rows being deleted in this batch). Returns the number of rows actually
// deleted in this call. Callers loop until 0 is returned to drain the backlog
// in batches.
func (d *DB) TrimAccessLogsFIFOBatch(ctx context.Context, maxRows int64, batchSize int) (PruneResult, error) {
	if maxRows < 0 {
		maxRows = 0
	}
	if batchSize <= 0 {
		batchSize = 1000
	}

	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return PruneResult{}, fmt.Errorf("failed to begin trim transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var total int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_logs`).Scan(&total); err != nil {
		return PruneResult{}, fmt.Errorf("failed to count access_logs in trim: %w", err)
	}
	excess := total - maxRows
	if excess <= 0 {
		return PruneResult{}, tx.Commit()
	}
	toDelete := excess
	if toDelete > int64(batchSize) {
		toDelete = int64(batchSize)
	}

	// Capture the lowest id about to be deleted in this batch — surfaced in
	// PruneResult so the retention manager can record the deleted range.
	var firstID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM access_logs ORDER BY id ASC LIMIT 1`).Scan(&firstID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PruneResult{}, tx.Commit()
		}
		return PruneResult{}, fmt.Errorf("failed to read FIFO lowest id: %w", err)
	}

	// Identify the highest id among the oldest `toDelete` rows. We delete by
	// id range (id <= cutId) inside the same transaction.
	var cutID sql.NullInt64
	var cutHash sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id, entry_hash FROM access_logs
		ORDER BY id ASC
		LIMIT 1 OFFSET $1`, toDelete-1).Scan(&cutID, &cutHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Race: rows disappeared between the COUNT and the OFFSET probe.
			return PruneResult{}, tx.Commit()
		}
		return PruneResult{}, fmt.Errorf("failed to read FIFO cut: %w", err)
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM access_logs WHERE id <= $1`, cutID.Int64)
	if err != nil {
		return PruneResult{}, fmt.Errorf("failed to trim access_logs: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return PruneResult{}, fmt.Errorf("failed to count trimmed rows: %w", err)
	}

	res := PruneResult{Deleted: deleted}
	if deleted > 0 && cutID.Valid {
		anchorHash := cutHash.String
		if !cutHash.Valid || anchorHash == "" {
			prev, perr := getAnchorHashTx(ctx, tx, ChainNameAccessLogs)
			if perr != nil {
				return PruneResult{}, perr
			}
			anchorHash = prev
		}
		if err := upsertAuditChainAnchorTx(ctx, tx, ChainNameAccessLogs, cutID.Int64, anchorHash); err != nil {
			return PruneResult{}, err
		}
		res.HighestID = cutID.Int64
		res.AnchorHash = anchorHash
		if firstID.Valid {
			res.LowestID = firstID.Int64
		}
	}

	if err := tx.Commit(); err != nil {
		return PruneResult{}, fmt.Errorf("failed to commit access log trim: %w", err)
	}
	return res, nil
}

// CleanupComplianceLogs deletes compliance log entries older than the given time.
func (d *DB) CleanupComplianceLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx, `DELETE FROM compliance_logs WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup compliance logs: %w", err)
	}
	return result.RowsAffected()
}

// CleanupRBACAuditLogs deletes RBAC audit log entries older than the given time.
func (d *DB) CleanupRBACAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx, `DELETE FROM rbac_audit_log WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup RBAC audit logs: %w", err)
	}
	return result.RowsAffected()
}

// CleanupUsedTravelRecords deletes used travel rule records older than the given time.
// Only deletes records that have been used (used_at IS NOT NULL).
func (d *DB) CleanupUsedTravelRecords(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM travel_rule_records WHERE used_at IS NOT NULL AND created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup used travel records: %w", err)
	}
	return result.RowsAffected()
}

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	TokenHash string
	Subject   string
	CreatedAt string
	ExpiresAt string
	Revoked   bool
	RevokedAt *string
}

// SaveRefreshToken saves a refresh token to the database
func (d *DB) SaveRefreshToken(ctx context.Context, tokenHash, subject string, expiresAt time.Time) error {
	query := `INSERT INTO refresh_tokens (token_hash, subject, expires_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT(token_hash) DO UPDATE SET
	          expires_at = excluded.expires_at,
	          revoked = false,
	          revoked_at = NULL`

	_, err := d.conn.ExecContext(ctx, query, tokenHash, subject, expiresAt)
	return err
}

// GetRefreshToken retrieves a refresh token by hash
func (d *DB) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	query := `SELECT token_hash, subject, created_at, expires_at, revoked, revoked_at
	          FROM refresh_tokens WHERE token_hash = $1`

	var token RefreshToken
	var revokedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.TokenHash,
		&token.Subject,
		&token.CreatedAt,
		&token.ExpiresAt,
		&token.Revoked,
		&revokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if revokedAt.Valid {
		revokedAtStr := revokedAt.String
		token.RevokedAt = &revokedAtStr
	}

	return &token, nil
}

// RevokeRefreshToken marks a refresh token as revoked
func (d *DB) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	query := `UPDATE refresh_tokens
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE token_hash = $1`

	_, err := d.conn.ExecContext(ctx, query, tokenHash)
	return err
}

// RevokeRefreshTokensBySubject revokes all active refresh tokens for a given subject.
// Used when banning a user to force immediate session termination.
func (d *DB) RevokeRefreshTokensBySubject(ctx context.Context, subject string) (int64, error) {
	query := `UPDATE refresh_tokens
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE subject = $1 AND revoked = false`

	result, err := d.conn.ExecContext(ctx, query, subject)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// RevokeAccessToken stores a revoked access token (for blacklist checking)
func (d *DB) RevokeAccessToken(ctx context.Context, tokenID, subject string, expiresAt time.Time) error {
	query := `INSERT INTO revoked_tokens (token_id, subject, expires_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT(token_id) DO NOTHING`

	_, err := d.conn.ExecContext(ctx, query, tokenID, subject, expiresAt)
	return err
}

// IsAccessTokenRevoked checks if an access token is revoked
func (d *DB) IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_id = $1)`

	var exists bool
	err := d.conn.QueryRowContext(ctx, query, tokenID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check revoked token: %w", err)
	}

	return exists, nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (d *DB) CleanupExpiredTokens(ctx context.Context) error {
	// Use current time from Go to ensure consistency with how tokens are stored
	now := time.Now()

	// Clean up expired refresh tokens
	_, err := d.conn.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}

	// Clean up expired revoked tokens
	_, err = d.conn.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired revoked tokens: %w", err)
	}

	return nil
}

// EthAddressLink represents a link between an Ethereum address and a DID
type EthAddressLink struct {
	ID            int     `json:"id"`
	DID           string  `json:"did"`
	EthAddress    string  `json:"eth_address"`
	Signature     string  `json:"signature"`
	MessageHash   string  `json:"message_hash"`
	VerifiedAt    string  `json:"verified_at"`
	Revoked       bool    `json:"revoked"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
	ENSName       *string `json:"ens_name,omitempty"`
	ENSResolvedAt *string `json:"ens_resolved_at,omitempty"`
	LinkType      string  `json:"link_type"`
}

// LinkEthAddress creates a new user-initiated link between an ETH address and a DID.
// If the (did, eth_address) pair already exists and is not revoked, it refreshes the signature
// and upgrades a system link to a user link.
// If the (did, eth_address) pair exists but is revoked, it returns ErrAddressLinkRevoked.
func (d *DB) LinkEthAddress(ctx context.Context, did, ethAddress, signature, messageHash string) error {
	query := `INSERT INTO eth_address_links (did, eth_address, signature, message_hash, link_type)
	          VALUES ($1, $2, $3, $4, 'user')
	          ON CONFLICT (did, eth_address) DO UPDATE SET
	          signature = excluded.signature,
	          message_hash = excluded.message_hash,
	          link_type = 'user',
	          verified_at = CURRENT_TIMESTAMP,
	          ens_name = NULL,
	          ens_resolved_at = NULL
	          WHERE eth_address_links.revoked = false`

	result, err := d.conn.ExecContext(ctx, query, did, ethAddress, signature, messageHash)
	if err != nil {
		return fmt.Errorf("failed to link ETH address: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check link result: %w", err)
	}
	if rowsAffected == 0 {
		// The (did, eth_address) pair exists but is revoked.
		return ErrAddressLinkRevoked
	}
	return nil
}

// isValidEthAddress returns true for 0x-prefixed 40-hex-character addresses.
func isValidEthAddress(address string) bool {
	if len(address) != 42 {
		return false
	}
	if address[0] != '0' || (address[1] != 'x' && address[1] != 'X') {
		return false
	}
	for _, c := range address[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// SystemLinkEthAddress records a system-level address→DID link when a user submits
// a transaction through the proxy. Unlike user-initiated links there is no signature.
// If the (did, eth_address) pair already exists (any link_type), this is a no-op.
func (d *DB) SystemLinkEthAddress(ctx context.Context, did, ethAddress string) error {
	if did == "" || ethAddress == "" {
		return nil
	}
	if !isValidEthAddress(ethAddress) {
		return fmt.Errorf("invalid ethereum address: %q", ethAddress)
	}
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eth_address_links (did, eth_address, link_type)
		VALUES ($1, $2, 'system')
		ON CONFLICT (did, eth_address) DO NOTHING`,
		did, strings.ToLower(ethAddress),
	)
	return err
}

// GetAllLinkedEOAAddresses returns all active ETH addresses linked to any user DID.
// Used for bulk visibility filtering to identify which addresses belong to users.
func (d *DB) GetAllLinkedEOAAddresses(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT LOWER(eth_address) FROM eth_address_links WHERE revoked = false`
	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all linked EOAs: %w", err)
	}
	defer rows.Close()

	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, rows.Err()
}

// GetEthAddressesByDID retrieves all ETH addresses linked to a DID
func (d *DB) GetEthAddressesByDID(ctx context.Context, did string) ([]*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at, link_type
	          FROM eth_address_links
	          WHERE did = $1 AND revoked = false
	          ORDER BY verified_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, did)
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH addresses: %w", err)
	}
	defer rows.Close()

	links := make([]*EthAddressLink, 0)
	for rows.Next() {
		var link EthAddressLink
		var signature, messageHash, revokedAt, ensName, ensResolvedAt sql.NullString

		if err := rows.Scan(
			&link.ID,
			&link.DID,
			&link.EthAddress,
			&signature,
			&messageHash,
			&link.VerifiedAt,
			&link.Revoked,
			&revokedAt,
			&ensName,
			&ensResolvedAt,
			&link.LinkType,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ETH address link: %w", err)
		}

		if signature.Valid {
			link.Signature = signature.String
		}
		if messageHash.Valid {
			link.MessageHash = messageHash.String
		}
		if revokedAt.Valid {
			link.RevokedAt = &revokedAt.String
		}
		if ensName.Valid {
			link.ENSName = &ensName.String
		}
		if ensResolvedAt.Valid {
			link.ENSResolvedAt = &ensResolvedAt.String
		}
		links = append(links, &link)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate ETH address links: %w", err)
	}

	return links, nil
}

// GetDIDByEthAddress retrieves the DID linked to an ETH address.
// With multiple DIDs per address now possible, prefers user-linked over system-linked,
// most recent first.
func (d *DB) GetDIDByEthAddress(ctx context.Context, ethAddress string) (string, error) {
	query := `SELECT did FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false
	          ORDER BY CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC
	          LIMIT 1`

	var did string
	err := d.conn.QueryRowContext(ctx, query, ethAddress).Scan(&did)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get DID by ETH address: %w", err)
	}
	return did, nil
}

// GetDIDsByEthAddress returns all non-revoked DIDs linked to an ETH address.
// Used for collision detection (same address claimed by multiple identities).
func (d *DB) GetDIDsByEthAddress(ctx context.Context, ethAddress string) ([]string, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT did FROM eth_address_links
		 WHERE eth_address = $1 AND revoked = false
		 ORDER BY CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC`,
		strings.ToLower(ethAddress),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get DIDs by ETH address: %w", err)
	}
	defer rows.Close()
	var dids []string
	for rows.Next() {
		var did string
		if err := rows.Scan(&did); err != nil {
			return nil, fmt.Errorf("failed to scan DID: %w", err)
		}
		dids = append(dids, did)
	}
	return dids, rows.Err()
}

// AddressLinkCollision represents an ETH address claimed by more than one DID.
type AddressLinkCollision struct {
	EthAddress string   `json:"eth_address"`
	DIDs       []string `json:"dids"`
	LinkTypes  []string `json:"link_types"`
}

// GetAddressLinkCollisions returns all ETH addresses that are linked to more
// than one non-revoked DID. Used by the admin dashboard to surface potential
// key-sharing or key-compromise events.
func (d *DB) GetAddressLinkCollisions(ctx context.Context) ([]*AddressLinkCollision, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT eth_address, did, link_type
		FROM eth_address_links
		WHERE revoked = false
		  AND eth_address IN (
		      SELECT eth_address FROM eth_address_links
		      WHERE revoked = false
		      GROUP BY eth_address HAVING COUNT(DISTINCT did) > 1
		  )
		ORDER BY eth_address, CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query address collisions: %w", err)
	}
	defer rows.Close()

	byAddr := make(map[string]*AddressLinkCollision)
	var order []string
	for rows.Next() {
		var addr, did, linkType string
		if err := rows.Scan(&addr, &did, &linkType); err != nil {
			return nil, fmt.Errorf("failed to scan collision row: %w", err)
		}
		if _, ok := byAddr[addr]; !ok {
			byAddr[addr] = &AddressLinkCollision{EthAddress: addr}
			order = append(order, addr)
		}
		byAddr[addr].DIDs = append(byAddr[addr].DIDs, did)
		byAddr[addr].LinkTypes = append(byAddr[addr].LinkTypes, linkType)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]*AddressLinkCollision, 0, len(order))
	for _, addr := range order {
		result = append(result, byAddr[addr])
	}
	return result, nil
}

// RevokeEthAddressLink revokes a link between an ETH address and a DID
// Only the DID owner can revoke their own links
func (d *DB) RevokeEthAddressLink(ctx context.Context, did, ethAddress string) error {
	query := `UPDATE eth_address_links
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE did = $1 AND eth_address = $2`

	result, err := d.conn.ExecContext(ctx, query, did, ethAddress)
	if err != nil {
		return fmt.Errorf("failed to revoke ETH address link: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no matching link found")
	}

	return nil
}

// UpdateENSName updates the ENS name for an ETH address
func (d *DB) UpdateENSName(ctx context.Context, ethAddress string, ensName *string) error {
	query := `UPDATE eth_address_links
	          SET ens_name = $2, ens_resolved_at = CURRENT_TIMESTAMP
	          WHERE eth_address = $1 AND revoked = false`

	_, err := d.conn.ExecContext(ctx, query, ethAddress, ensName)
	if err != nil {
		return fmt.Errorf("failed to update ENS name: %w", err)
	}
	return nil
}

// GetEthAddressLink retrieves a specific ETH address link.
// With multiple DIDs per address now possible, returns the best match
// (user-linked preferred over system-linked, most recent first).
func (d *DB) GetEthAddressLink(ctx context.Context, ethAddress string) (*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at, link_type
	          FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false
	          ORDER BY CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC
	          LIMIT 1`

	var link EthAddressLink
	var signature, messageHash, revokedAt, ensName, ensResolvedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, ethAddress).Scan(
		&link.ID,
		&link.DID,
		&link.EthAddress,
		&signature,
		&messageHash,
		&link.VerifiedAt,
		&link.Revoked,
		&revokedAt,
		&ensName,
		&ensResolvedAt,
		&link.LinkType,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH address link: %w", err)
	}

	if signature.Valid {
		link.Signature = signature.String
	}
	if messageHash.Valid {
		link.MessageHash = messageHash.String
	}
	if revokedAt.Valid {
		link.RevokedAt = &revokedAt.String
	}
	if ensName.Valid {
		link.ENSName = &ensName.String
	}
	if ensResolvedAt.Valid {
		link.ENSResolvedAt = &ensResolvedAt.String
	}

	return &link, nil
}

// GetEthAddressLinkForDID retrieves the ETH address link for a specific (did, eth_address) pair.
// Unlike GetEthAddressLink, this is scoped to a single DID and is not affected by
// multiple DIDs sharing the same address.
func (d *DB) GetEthAddressLinkForDID(ctx context.Context, did, ethAddress string) (*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at, link_type
	          FROM eth_address_links
	          WHERE did = $1 AND eth_address = $2 AND revoked = false
	          LIMIT 1`

	var link EthAddressLink
	var signature, messageHash, revokedAt, ensName, ensResolvedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, did, ethAddress).Scan(
		&link.ID,
		&link.DID,
		&link.EthAddress,
		&signature,
		&messageHash,
		&link.VerifiedAt,
		&link.Revoked,
		&revokedAt,
		&ensName,
		&ensResolvedAt,
		&link.LinkType,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH address link for DID: %w", err)
	}

	if signature.Valid {
		link.Signature = signature.String
	}
	if messageHash.Valid {
		link.MessageHash = messageHash.String
	}
	if revokedAt.Valid {
		link.RevokedAt = &revokedAt.String
	}
	if ensName.Valid {
		link.ENSName = &ensName.String
	}
	if ensResolvedAt.Valid {
		link.ENSResolvedAt = &ensResolvedAt.String
	}

	return &link, nil
}
