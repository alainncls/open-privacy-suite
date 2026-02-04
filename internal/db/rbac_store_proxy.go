package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"
)

// Managed Proxy operations

// CreateManagedProxy inserts a new managed proxy record.
func (d *DB) CreateManagedProxy(ctx context.Context, proxy *rbac.ManagedProxy) error {
	query := `
		INSERT INTO managed_proxies (id, org_id, proxy_address, proxy_type, current_impl)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`

	var currentImpl sql.NullString
	if proxy.CurrentImpl != "" {
		currentImpl = sql.NullString{String: strings.ToLower(proxy.CurrentImpl), Valid: true}
	}

	err := d.conn.QueryRowContext(ctx, query,
		proxy.ID,
		proxy.OrgID,
		strings.ToLower(proxy.ProxyAddress),
		proxy.ProxyType,
		currentImpl,
	).Scan(&proxy.CreatedAt, &proxy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create managed proxy: %w", err)
	}

	return nil
}

// GetManagedProxy retrieves a managed proxy by its address.
func (d *DB) GetManagedProxy(ctx context.Context, address string) (*rbac.ManagedProxy, error) {
	query := `
		SELECT id, org_id, proxy_address, proxy_type, current_impl, created_at, updated_at
		FROM managed_proxies
		WHERE LOWER(proxy_address) = LOWER($1)
	`

	return scanManagedProxy(d.conn.QueryRowContext(ctx, query, address))
}

// UpdateManagedProxyImpl updates the current implementation address of a managed proxy.
func (d *DB) UpdateManagedProxyImpl(ctx context.Context, address, newImpl string) error {
	result, err := d.conn.ExecContext(ctx, `
		UPDATE managed_proxies
		SET current_impl = LOWER($2), updated_at = CURRENT_TIMESTAMP
		WHERE LOWER(proxy_address) = LOWER($1)
	`, address, newImpl)
	if err != nil {
		return fmt.Errorf("failed to update managed proxy implementation: %w", err)
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

// IsManagedProxy checks if an address is a managed proxy.
func (d *DB) IsManagedProxy(ctx context.Context, address string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM managed_proxies WHERE LOWER(proxy_address) = LOWER($1))`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, address).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check managed proxy: %w", err)
	}
	return exists, nil
}

// ListManagedProxies returns all managed proxies for an organization.
func (d *DB) ListManagedProxies(ctx context.Context, orgID string) ([]*rbac.ManagedProxy, error) {
	query := `
		SELECT id, org_id, proxy_address, proxy_type, current_impl, created_at, updated_at
		FROM managed_proxies
		WHERE org_id = $1
		ORDER BY created_at DESC
	`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list managed proxies: %w", err)
	}
	defer rows.Close()

	var proxies []*rbac.ManagedProxy
	for rows.Next() {
		proxy := &rbac.ManagedProxy{}
		var currentImpl sql.NullString

		err := rows.Scan(
			&proxy.ID,
			&proxy.OrgID,
			&proxy.ProxyAddress,
			&proxy.ProxyType,
			&currentImpl,
			&proxy.CreatedAt,
			&proxy.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan managed proxy: %w", err)
		}

		if currentImpl.Valid {
			proxy.CurrentImpl = currentImpl.String
		}
		proxies = append(proxies, proxy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate managed proxies: %w", err)
	}

	return proxies, nil
}

func scanManagedProxy(row *sql.Row) (*rbac.ManagedProxy, error) {
	proxy := &rbac.ManagedProxy{}
	var currentImpl sql.NullString

	err := row.Scan(
		&proxy.ID,
		&proxy.OrgID,
		&proxy.ProxyAddress,
		&proxy.ProxyType,
		&currentImpl,
		&proxy.CreatedAt,
		&proxy.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan managed proxy: %w", err)
	}

	if currentImpl.Valid {
		proxy.CurrentImpl = currentImpl.String
	}

	return proxy, nil
}
