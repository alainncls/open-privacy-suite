package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/tern/v2/migrate"

	"privacy-proxy/internal/db/migrations"
)

// ErrAddressAlreadyLinked is returned when an ETH address is already linked to a different DID.
var ErrAddressAlreadyLinked = errors.New("ETH address is already linked to a different identity")

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
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	ctx := context.Background()
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
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
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
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
	ID            int              `json:"id"`
	ExternalID    string           `json:"external_id"`
	Method        string           `json:"method"`
	StatusCode    int              `json:"status_code"`
	IPAddress     string           `json:"ip_address"`
	CorrelationID *string          `json:"correlation_id,omitempty"`
	RequestParams *json.RawMessage `json:"request_params,omitempty"`
	EntryHash     *string          `json:"entry_hash,omitempty"`
	CreatedAt     string           `json:"created_at"`
}

func (d *DB) GetAccessLogs(ctx context.Context, limit int) ([]*AccessLog, error) {
	query := `SELECT id, external_id, method, status_code, ip_address,
	          correlation_id, request_params, entry_hash, created_at
	          FROM access_logs
	          ORDER BY created_at DESC
	          LIMIT $1`

	rows, err := d.conn.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*AccessLog, 0)

	for rows.Next() {
		var log AccessLog
		var correlationID, entryHash sql.NullString
		var requestParams []byte

		if err := rows.Scan(
			&log.ID,
			&log.ExternalID,
			&log.Method,
			&log.StatusCode,
			&log.IPAddress,
			&correlationID,
			&requestParams,
			&entryHash,
			&log.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan log: %w", err)
		}

		if correlationID.Valid {
			log.CorrelationID = &correlationID.String
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

// LogAccessEnhanced inserts an access log entry with correlation ID, optional request params, and returns the ID and created_at for hash chain computation.
func (d *DB) LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte) (int64, time.Time, error) {
	query := `INSERT INTO access_logs (external_id, method, status_code, ip_address, correlation_id, request_params)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING id, created_at`

	var id int64
	var createdAt time.Time
	var corrID *string
	if correlationID != "" {
		corrID = &correlationID
	}

	err := d.conn.QueryRowContext(ctx, query, externalID, method, statusCode, ipAddress, corrID, params).Scan(&id, &createdAt)
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

// GetLatestAccessLogHash returns the entry_hash of the most recent access log entry that has one.
// Used to seed the hash chain on startup.
func (d *DB) GetLatestAccessLogHash(ctx context.Context) (string, error) {
	var hash sql.NullString
	err := d.conn.QueryRowContext(ctx,
		`SELECT entry_hash FROM access_logs WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
	).Scan(&hash)
	if err == sql.ErrNoRows || !hash.Valid {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get latest access log hash: %w", err)
	}
	return hash.String, nil
}

// CleanupAccessLogs deletes access log entries older than the given time.
func (d *DB) CleanupAccessLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx, `DELETE FROM access_logs WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup access logs: %w", err)
	}
	return result.RowsAffected()
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
}

// LinkEthAddress creates a new link between an ETH address and a DID.
// If the address is already linked to the same DID (and not revoked), it refreshes the signature.
// If the address is already linked to a different DID, it returns ErrAddressAlreadyLinked.
// If the address link was revoked by an admin, it returns ErrAddressLinkRevoked.
func (d *DB) LinkEthAddress(ctx context.Context, did, ethAddress, signature, messageHash string) error {
	// If the address is already linked to the SAME DID and NOT revoked, we refresh the signature.
	// If it's already linked to a DIFFERENT DID, or if it's already REVOKED, the update fails
	// and we return the appropriate error below.
	query := `INSERT INTO eth_address_links (did, eth_address, signature, message_hash)
	          VALUES ($1, $2, $3, $4)
	          ON CONFLICT (eth_address) DO UPDATE SET
	          signature = excluded.signature,
	          message_hash = excluded.message_hash,
	          verified_at = CURRENT_TIMESTAMP,
	          ens_name = NULL,
	          ens_resolved_at = NULL
	          WHERE eth_address_links.did = excluded.did
	          AND eth_address_links.revoked = false`

	result, err := d.conn.ExecContext(ctx, query, did, ethAddress, signature, messageHash)
	if err != nil {
		return fmt.Errorf("failed to link ETH address: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check link result: %w", err)
	}
	if rowsAffected == 0 {
		// Distinguish: different DID vs same DID but revoked
		var existingDID string
		var revoked bool
		err := d.conn.QueryRowContext(ctx,
			`SELECT did, revoked FROM eth_address_links WHERE eth_address = $1`,
			ethAddress,
		).Scan(&existingDID, &revoked)
		if err != nil {
			return fmt.Errorf("failed to check existing link: %w", err)
		}
		if existingDID != did {
			return ErrAddressAlreadyLinked
		}
		if revoked {
			return ErrAddressLinkRevoked
		}
		// Same DID, not revoked — shouldn't happen, but treat as success
		return nil
	}
	return nil
}

// GetEthAddressesByDID retrieves all ETH addresses linked to a DID
func (d *DB) GetEthAddressesByDID(ctx context.Context, did string) ([]*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at
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
		var revokedAt, ensName, ensResolvedAt sql.NullString

		if err := rows.Scan(
			&link.ID,
			&link.DID,
			&link.EthAddress,
			&link.Signature,
			&link.MessageHash,
			&link.VerifiedAt,
			&link.Revoked,
			&revokedAt,
			&ensName,
			&ensResolvedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ETH address link: %w", err)
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

// GetDIDByEthAddress retrieves the DID linked to an ETH address
func (d *DB) GetDIDByEthAddress(ctx context.Context, ethAddress string) (string, error) {
	query := `SELECT did FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false`

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

// GetEthAddressLink retrieves a specific ETH address link
func (d *DB) GetEthAddressLink(ctx context.Context, ethAddress string) (*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at
	          FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false`

	var link EthAddressLink
	var revokedAt, ensName, ensResolvedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, ethAddress).Scan(
		&link.ID,
		&link.DID,
		&link.EthAddress,
		&link.Signature,
		&link.MessageHash,
		&link.VerifiedAt,
		&link.Revoked,
		&revokedAt,
		&ensName,
		&ensResolvedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH address link: %w", err)
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
