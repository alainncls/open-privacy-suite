package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/tern/v2/migrate"

	"privacy-proxy/internal/db/migrations"
)

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

func (d *DB) LogAccess(externalID, method string, statusCode int, ipAddress string) error {
	query := `INSERT INTO access_logs (external_id, method, status_code, ip_address)
	          VALUES ($1, $2, $3, $4)`
	
	_, err := d.conn.Exec(query, externalID, method, statusCode, ipAddress)
	return err
}

type AccessLog struct {
	ID         int    `json:"id"`
	ExternalID string `json:"external_id"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
}

func (d *DB) GetAccessLogs(limit int) ([]*AccessLog, error) {
	query := `SELECT id, external_id, method, status_code, ip_address, created_at
	          FROM access_logs 
	          ORDER BY created_at DESC 
	          LIMIT $1`
	
	rows, err := d.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer rows.Close()
	
	logs := make([]*AccessLog, 0)

	for rows.Next() {
		var log AccessLog
		if err := rows.Scan(
			&log.ID,
			&log.ExternalID,
			&log.Method,
			&log.StatusCode,
			&log.IPAddress,
			&log.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan log: %w", err)
		}

		logs = append(logs, &log)
	}

	return logs, nil
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
func (d *DB) SaveRefreshToken(tokenHash, subject string, expiresAt time.Time) error {
	query := `INSERT INTO refresh_tokens (token_hash, subject, expires_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT(token_hash) DO UPDATE SET
	          expires_at = excluded.expires_at,
	          revoked = false,
	          revoked_at = NULL`
	
	_, err := d.conn.Exec(query, tokenHash, subject, expiresAt)
	return err
}

// GetRefreshToken retrieves a refresh token by hash
func (d *DB) GetRefreshToken(tokenHash string) (*RefreshToken, error) {
	query := `SELECT token_hash, subject, created_at, expires_at, revoked, revoked_at
	          FROM refresh_tokens WHERE token_hash = $1`
	
	var token RefreshToken
	var revokedAt sql.NullString
	
	err := d.conn.QueryRow(query, tokenHash).Scan(
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
func (d *DB) RevokeRefreshToken(tokenHash string) error {
	query := `UPDATE refresh_tokens 
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE token_hash = $1`
	
	_, err := d.conn.Exec(query, tokenHash)
	return err
}

// RevokeAccessToken stores a revoked access token (for blacklist checking)
func (d *DB) RevokeAccessToken(tokenID, subject string, expiresAt time.Time) error {
	query := `INSERT INTO revoked_tokens (token_id, subject, expires_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT(token_id) DO NOTHING`
	
	_, err := d.conn.Exec(query, tokenID, subject, expiresAt)
	return err
}

// IsAccessTokenRevoked checks if an access token is revoked
func (d *DB) IsAccessTokenRevoked(tokenID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_id = $1)`
	
	var exists bool
	err := d.conn.QueryRow(query, tokenID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check revoked token: %w", err)
	}
	
	return exists, nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (d *DB) CleanupExpiredTokens() error {
	// Use current time from Go to ensure consistency with how tokens are stored
	now := time.Now()

	// Clean up expired refresh tokens
	_, err := d.conn.Exec(`DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}

	// Clean up expired revoked tokens
	_, err = d.conn.Exec(`DELETE FROM revoked_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired revoked tokens: %w", err)
	}

	return nil
}

// EthAddressLink represents a link between an Ethereum address and a DID
type EthAddressLink struct {
	ID          int     `json:"id"`
	DID         string  `json:"did"`
	EthAddress  string  `json:"eth_address"`
	Signature   string  `json:"signature"`
	MessageHash string  `json:"message_hash"`
	VerifiedAt  string  `json:"verified_at"`
	Revoked     bool    `json:"revoked"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
}

// LinkEthAddress creates a new link between an ETH address and a DID
// The ETH address must not already be linked to another DID
func (d *DB) LinkEthAddress(did, ethAddress, signature, messageHash string) error {
	query := `INSERT INTO eth_address_links (did, eth_address, signature, message_hash)
	          VALUES ($1, $2, $3, $4)
	          ON CONFLICT (eth_address) DO UPDATE SET
	          did = excluded.did,
	          signature = excluded.signature,
	          message_hash = excluded.message_hash,
	          verified_at = CURRENT_TIMESTAMP,
	          revoked = false,
	          revoked_at = NULL`

	_, err := d.conn.Exec(query, did, ethAddress, signature, messageHash)
	if err != nil {
		return fmt.Errorf("failed to link ETH address: %w", err)
	}
	return nil
}

// GetEthAddressesByDID retrieves all ETH addresses linked to a DID
func (d *DB) GetEthAddressesByDID(did string) ([]*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at
	          FROM eth_address_links
	          WHERE did = $1 AND revoked = false
	          ORDER BY verified_at DESC`

	rows, err := d.conn.Query(query, did)
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH addresses: %w", err)
	}
	defer rows.Close()

	links := make([]*EthAddressLink, 0)
	for rows.Next() {
		var link EthAddressLink
		var revokedAt sql.NullString

		if err := rows.Scan(
			&link.ID,
			&link.DID,
			&link.EthAddress,
			&link.Signature,
			&link.MessageHash,
			&link.VerifiedAt,
			&link.Revoked,
			&revokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ETH address link: %w", err)
		}

		if revokedAt.Valid {
			link.RevokedAt = &revokedAt.String
		}
		links = append(links, &link)
	}

	return links, nil
}

// GetDIDByEthAddress retrieves the DID linked to an ETH address
func (d *DB) GetDIDByEthAddress(ethAddress string) (string, error) {
	query := `SELECT did FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false`

	var did string
	err := d.conn.QueryRow(query, ethAddress).Scan(&did)
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
func (d *DB) RevokeEthAddressLink(did, ethAddress string) error {
	query := `UPDATE eth_address_links
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE did = $1 AND eth_address = $2`

	result, err := d.conn.Exec(query, did, ethAddress)
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
