package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"
)

// Shared Infrastructure operations

// IsSharedInfrastructure checks if an address is registered as shared infrastructure.
func (d *DB) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM shared_infrastructure WHERE LOWER(address) = LOWER($1))`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, address).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check shared infrastructure: %w", err)
	}
	return exists, nil
}

// CreateSharedInfrastructure inserts a new shared infrastructure record.
func (d *DB) CreateSharedInfrastructure(ctx context.Context, infra *rbac.SharedInfrastructure) error {
	query := `
		INSERT INTO shared_infrastructure (address, name, description)
		VALUES ($1, $2, $3)
		RETURNING created_at
	`

	var description sql.NullString
	if infra.Description != "" {
		description = sql.NullString{String: infra.Description, Valid: true}
	}

	err := d.conn.QueryRowContext(ctx, query,
		strings.ToLower(infra.Address),
		infra.Name,
		description,
	).Scan(&infra.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create shared infrastructure: %w", err)
	}

	return nil
}

// ListSharedInfrastructure returns all shared infrastructure records.
func (d *DB) ListSharedInfrastructure(ctx context.Context) ([]*rbac.SharedInfrastructure, error) {
	query := `
		SELECT address, name, description, created_at
		FROM shared_infrastructure
		ORDER BY created_at DESC
	`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list shared infrastructure: %w", err)
	}
	defer rows.Close()

	return scanSharedInfrastructureRows(rows)
}

// DeleteSharedInfrastructure removes a shared infrastructure record by address.
func (d *DB) DeleteSharedInfrastructure(ctx context.Context, address string) error {
	result, err := d.conn.ExecContext(ctx, `
		DELETE FROM shared_infrastructure
		WHERE LOWER(address) = LOWER($1)
	`, address)
	if err != nil {
		return fmt.Errorf("failed to delete shared infrastructure: %w", err)
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

func scanSharedInfrastructureRows(rows *sql.Rows) ([]*rbac.SharedInfrastructure, error) {
	var infras []*rbac.SharedInfrastructure
	for rows.Next() {
		infra := &rbac.SharedInfrastructure{}
		var description sql.NullString

		if err := rows.Scan(
			&infra.Address,
			&infra.Name,
			&description,
			&infra.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan shared infrastructure: %w", err)
		}

		if description.Valid {
			infra.Description = description.String
		}

		infras = append(infras, infra)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating shared infrastructure: %w", err)
	}

	return infras, nil
}
