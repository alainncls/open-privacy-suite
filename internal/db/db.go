package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

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
	
	CREATE INDEX IF NOT EXISTS idx_logs_external_id ON access_logs(external_id);
	CREATE INDEX IF NOT EXISTS idx_logs_created_at ON access_logs(created_at);
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
