package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"
)

// Preregistered Address operations

// CreatePreregisteredAddresses bulk inserts preregistered addresses.
func (d *DB) CreatePreregisteredAddresses(ctx context.Context, addresses []*rbac.PreregisteredAddress) error {
	if len(addresses) == 0 {
		return nil
	}

	// Use a transaction for bulk insert
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO preregistered_addresses (id, org_id, address, factory, salt, note)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, addr := range addresses {
		err := stmt.QueryRowContext(ctx,
			addr.ID, addr.OrgID, strings.ToLower(addr.Address),
			strings.ToLower(addr.Factory), addr.Salt, addr.Note,
		).Scan(&addr.CreatedAt)
		if err != nil {
			return fmt.Errorf("failed to insert preregistered address %s: %w", addr.Address, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListPreregisteredAddresses returns all preregistered addresses for an organization.
func (d *DB) ListPreregisteredAddresses(ctx context.Context, orgID string) ([]*rbac.PreregisteredAddress, error) {
	query := `
		SELECT id, org_id, address, factory, salt, note, created_at, used_at
		FROM preregistered_addresses
		WHERE org_id = $1
		ORDER BY created_at DESC
	`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list preregistered addresses: %w", err)
	}
	defer rows.Close()

	return scanPreregisteredAddresses(rows)
}

// GetPreregisteredAddressByAddress returns a preregistered address by its address within an org.
func (d *DB) GetPreregisteredAddressByAddress(ctx context.Context, orgID, address string) (*rbac.PreregisteredAddress, error) {
	query := `
		SELECT id, org_id, address, factory, salt, note, created_at, used_at
		FROM preregistered_addresses
		WHERE org_id = $1 AND LOWER(address) = LOWER($2)
	`

	return scanPreregisteredAddress(d.conn.QueryRowContext(ctx, query, orgID, address))
}

// DeletePreregisteredAddress removes a preregistered address.
func (d *DB) DeletePreregisteredAddress(ctx context.Context, orgID, address string) error {
	result, err := d.conn.ExecContext(ctx, `
		DELETE FROM preregistered_addresses
		WHERE org_id = $1 AND LOWER(address) = LOWER($2)
	`, orgID, address)
	if err != nil {
		return fmt.Errorf("failed to delete preregistered address: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// IsAddressPreregistered checks if an address is preregistered for the given org.
func (d *DB) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM preregistered_addresses WHERE LOWER(address) = LOWER($1) AND org_id = $2)`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, address, orgID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check preregistered address: %w", err)
	}
	return exists, nil
}

// MarkAddressUsed marks a preregistered address as used (deployed).
func (d *DB) MarkAddressUsed(ctx context.Context, address string) error {
	result, err := d.conn.ExecContext(ctx, `
		UPDATE preregistered_addresses
		SET used_at = CURRENT_TIMESTAMP
		WHERE LOWER(address) = LOWER($1) AND used_at IS NULL
	`, address)
	if err != nil {
		return fmt.Errorf("failed to mark address as used: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// Address not found or already marked as used - not an error
		return nil
	}

	return nil
}

func scanPreregisteredAddress(row *sql.Row) (*rbac.PreregisteredAddress, error) {
	addr := &rbac.PreregisteredAddress{}
	var note sql.NullString
	var usedAt sql.NullTime

	err := row.Scan(
		&addr.ID, &addr.OrgID, &addr.Address, &addr.Factory,
		&addr.Salt, &note, &addr.CreatedAt, &usedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan preregistered address: %w", err)
	}

	if note.Valid {
		addr.Note = note.String
	}
	if usedAt.Valid {
		addr.UsedAt = &usedAt.Time
	}

	return addr, nil
}

func scanPreregisteredAddresses(rows *sql.Rows) ([]*rbac.PreregisteredAddress, error) {
	var addresses []*rbac.PreregisteredAddress
	for rows.Next() {
		addr := &rbac.PreregisteredAddress{}
		var note sql.NullString
		var usedAt sql.NullTime

		if err := rows.Scan(
			&addr.ID, &addr.OrgID, &addr.Address, &addr.Factory,
			&addr.Salt, &note, &addr.CreatedAt, &usedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan preregistered address: %w", err)
		}

		if note.Valid {
			addr.Note = note.String
		}
		if usedAt.Valid {
			addr.UsedAt = &usedAt.Time
		}

		addresses = append(addresses, addr)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating preregistered addresses: %w", err)
	}

	return addresses, nil
}
