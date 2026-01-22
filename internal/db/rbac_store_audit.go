package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"privacy-proxy/internal/rbac"
)

// Audit Log operations

func (d *DB) CreateAuditLog(ctx context.Context, entry *rbac.AuditLogEntry) error {
	query := `INSERT INTO rbac_audit_log (actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING id, created_at`

	var oldValue, newValue []byte
	var err error

	if entry.OldValue != nil {
		oldValue, err = json.Marshal(entry.OldValue)
		if err != nil {
			return fmt.Errorf("failed to marshal old value: %w", err)
		}
	}

	if entry.NewValue != nil {
		newValue, err = json.Marshal(entry.NewValue)
		if err != nil {
			return fmt.Errorf("failed to marshal new value: %w", err)
		}
	}

	return d.conn.QueryRowContext(ctx, query,
		entry.ActorID, entry.ActorExternalID, entry.Action, entry.ResourceType,
		entry.ResourceID, entry.ResourceName, oldValue, newValue, entry.IPAddress,
	).Scan(&entry.ID, &entry.CreatedAt)
}

func (d *DB) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	var query string
	var args []any

	if resourceID != nil {
		query = `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address, created_at
		         FROM rbac_audit_log WHERE resource_type = $1 AND resource_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
		args = []any{resourceType, *resourceID, limit, offset}
	} else {
		query = `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address, created_at
		         FROM rbac_audit_log WHERE resource_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []any{resourceType, limit, offset}
	}

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func (d *DB) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	query := `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address, created_at
	          FROM rbac_audit_log WHERE actor_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, actorID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func scanAuditLogs(rows *sql.Rows) ([]*rbac.AuditLogEntry, error) {
	var entries []*rbac.AuditLogEntry
	for rows.Next() {
		entry := &rbac.AuditLogEntry{}
		var actorID, resourceID sql.NullString
		var oldValue, newValue []byte

		if err := rows.Scan(
			&entry.ID, &actorID, &entry.ActorExternalID, &entry.Action, &entry.ResourceType,
			&resourceID, &entry.ResourceName, &oldValue, &newValue, &entry.IPAddress,
			&entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if actorID.Valid {
			entry.ActorID = &actorID.String
		}
		if resourceID.Valid {
			entry.ResourceID = &resourceID.String
		}

		if len(oldValue) > 0 {
			if err := json.Unmarshal(oldValue, &entry.OldValue); err != nil {
				return nil, fmt.Errorf("failed to unmarshal old value: %w", err)
			}
		}

		if len(newValue) > 0 {
			if err := json.Unmarshal(newValue, &entry.NewValue); err != nil {
				return nil, fmt.Errorf("failed to unmarshal new value: %w", err)
			}
		}

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return entries, nil
}
