package db

import (
	"context"
	"fmt"
	"strings"
)

// Preregistered Address operations
// These support the plain CREATE pre-registration flow (pre-reg → mine → finalize).

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

// PreRegisterPlainCreate inserts a temporary preregistered_addresses row for a plain CREATE.
func (d *DB) PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO preregistered_addresses (id, org_id, address, factory, salt, note)
		VALUES (gen_random_uuid(), $1, $2, NULL, NULL, $3)
		ON CONFLICT (address) DO NOTHING
	`, orgID, strings.ToLower(address), note)
	if err != nil {
		return fmt.Errorf("failed to pre-register plain CREATE address: %w", err)
	}
	return nil
}

// DeletePreregisteredAddressByAddress removes a preregistered address by address (no org filter).
func (d *DB) DeletePreregisteredAddressByAddress(ctx context.Context, address string) error {
	_, err := d.conn.ExecContext(ctx, `
		DELETE FROM preregistered_addresses WHERE LOWER(address) = LOWER($1)
	`, address)
	if err != nil {
		return fmt.Errorf("failed to delete preregistered address: %w", err)
	}
	return nil
}

