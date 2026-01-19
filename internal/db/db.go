package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type DB struct {
	conn *sql.DB
}

// Conn returns the underlying database connection (for testing)
func (d *DB) Conn() *sql.DB {
	return d.conn
}

type AccessPolicy struct {
	ExternalID   string   `json:"external_id"`
	KYC          bool     `json:"kyc"`
	AllowMethods []string `json:"allow_methods"`
	Banned       bool     `json:"banned"`
	Note         string   `json:"note"`
}

// PolicyStore is an interface for policy storage operations
// This allows business logic to be tested with mocks instead of requiring a real database
type PolicyStore interface {
	GetPolicy(externalID string) (*AccessPolicy, error)
	SetPolicy(policy *AccessPolicy) error
	ListPolicies() ([]*AccessPolicy, error)
	DeletePolicy(externalID string) error
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
	
	db := &DB{conn: conn}
	
	if err := db.Migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}
	
	return db, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

func (d *DB) Migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS access_policies (
		external_id VARCHAR(255) PRIMARY KEY,
		kyc BOOLEAN NOT NULL DEFAULT false,
		allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
		banned BOOLEAN NOT NULL DEFAULT false,
		note TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS access_logs (
		id SERIAL PRIMARY KEY,
		external_id VARCHAR(255) NOT NULL,
		method VARCHAR(100) NOT NULL,
		status_code INTEGER NOT NULL,
		ip_address VARCHAR(45),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	-- Drop foreign key constraint if it exists (for existing databases)
	DO $$ 
	BEGIN
		IF EXISTS (
			SELECT 1 FROM information_schema.table_constraints 
			WHERE constraint_name = 'access_logs_external_id_fkey'
		) THEN
			ALTER TABLE access_logs DROP CONSTRAINT access_logs_external_id_fkey;
		END IF;
	END $$;
	
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token_hash VARCHAR(255) PRIMARY KEY,
		subject VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT false,
		revoked_at TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS revoked_tokens (
		token_id VARCHAR(255) PRIMARY KEY,
		subject VARCHAR(255) NOT NULL,
		revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL
	);
	
	CREATE INDEX IF NOT EXISTS idx_logs_external_id ON access_logs(external_id);
	CREATE INDEX IF NOT EXISTS idx_logs_created_at ON access_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_subject ON refresh_tokens(subject);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_subject ON revoked_tokens(subject);
	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);
	`
	
	_, err := d.conn.Exec(query)
	return err
}

func (d *DB) GetPolicy(externalID string) (*AccessPolicy, error) {
	query := `SELECT external_id, kyc, allow_methods, banned, note 
	          FROM access_policies WHERE external_id = $1`
	
	var policy AccessPolicy
	var methodsJSON []byte
	
	err := d.conn.QueryRow(query, externalID).Scan(
		&policy.ExternalID,
		&policy.KYC,
		&methodsJSON,
		&policy.Banned,
		&policy.Note,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	
	if err := json.Unmarshal(methodsJSON, &policy.AllowMethods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal methods: %w", err)
	}
	// Ensure AllowMethods is never nil
	if policy.AllowMethods == nil {
		policy.AllowMethods = []string{}
	}
	
	return &policy, nil
}

func (d *DB) SetPolicy(policy *AccessPolicy) error {
	// Ensure AllowMethods is never nil
	if policy.AllowMethods == nil {
		policy.AllowMethods = []string{}
	}
	methodsJSON, err := json.Marshal(policy.AllowMethods)
	if err != nil {
		return fmt.Errorf("failed to marshal methods: %w", err)
	}
	
	query := `INSERT INTO access_policies 
	          (external_id, kyc, allow_methods, banned, note, updated_at)
	          VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
	          ON CONFLICT(external_id) DO UPDATE SET
	          kyc = excluded.kyc,
	          allow_methods = excluded.allow_methods,
	          banned = excluded.banned,
	          note = excluded.note,
	          updated_at = CURRENT_TIMESTAMP`
	
	_, err = d.conn.Exec(query,
		policy.ExternalID,
		policy.KYC,
		methodsJSON,
		policy.Banned,
		policy.Note,
	)
	
	return err
}

func (d *DB) ListPolicies() ([]*AccessPolicy, error) {
	query := `SELECT external_id, kyc, allow_methods, banned, note 
	          FROM access_policies ORDER BY created_at DESC`
	
	rows, err := d.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()
	
	var policies []*AccessPolicy
	
	for rows.Next() {
		var policy AccessPolicy
		var methodsJSON []byte
		
		if err := rows.Scan(
			&policy.ExternalID,
			&policy.KYC,
			&methodsJSON,
			&policy.Banned,
			&policy.Note,
		); err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		
		if err := json.Unmarshal(methodsJSON, &policy.AllowMethods); err != nil {
			return nil, fmt.Errorf("failed to unmarshal methods: %w", err)
		}
		// Ensure AllowMethods is never nil
		if policy.AllowMethods == nil {
			policy.AllowMethods = []string{}
		}
		
		policies = append(policies, &policy)
	}
	
	return policies, nil
}

func (d *DB) DeletePolicy(externalID string) error {
	query := `DELETE FROM access_policies WHERE external_id = $1`
	_, err := d.conn.Exec(query, externalID)
	return err
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
	
	var logs []*AccessLog
	
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
