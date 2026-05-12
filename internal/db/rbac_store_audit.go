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
	query := `INSERT INTO rbac_audit_log (actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
		entry.ResourceID, entry.ResourceName, entry.OrgID, oldValue, newValue, entry.IPAddress,
	).Scan(&entry.ID, &entry.CreatedAt)
}

// ListAuditLogs returns audit log rows for super-admin / dev callers (no
// org filter). Deprecated — use ListAuditLogsScoped to apply cross-org
// filtering for JWT admin callers.
func (d *DB) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	return d.ListAuditLogsScoped(ctx, resourceType, resourceID, nil, limit, offset)
}

// ListAuditLogsScoped filters rows to those whose org_id is in
// scopedOrgIDs. Pass nil to disable filtering (super-admin path).
// Passing an empty (non-nil) slice returns zero rows (the JWT admin
// has no orgs and must see nothing).
//
// Rows with NULL org_id (pre-existing entries written before migration
// 051) are only visible when no filter is applied — they are treated
// as super-admin-only audit history.
func (d *DB) ListAuditLogsScoped(ctx context.Context, resourceType string, resourceID *string, scopedOrgIDs []string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	if scopedOrgIDs != nil && len(scopedOrgIDs) == 0 {
		// Caller is a JWT admin with no full or read-only orgs. Pre-fix
		// they could read everything; now they see nothing.
		return []*rbac.AuditLogEntry{}, nil
	}

	base := `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address, created_at
	         FROM rbac_audit_log WHERE resource_type = $1`
	args := []any{resourceType}
	idx := 2

	if resourceID != nil {
		base += fmt.Sprintf(" AND resource_id = $%d", idx)
		args = append(args, *resourceID)
		idx++
	}
	if scopedOrgIDs != nil {
		base += fmt.Sprintf(" AND org_id = ANY($%d)", idx)
		args = append(args, scopedOrgIDs)
		idx++
	}
	base += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, base, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func (d *DB) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	return d.ListAuditLogsByActorScoped(ctx, actorID, nil, limit, offset)
}

func (d *DB) ListAuditLogsByActorScoped(ctx context.Context, actorID string, scopedOrgIDs []string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	if scopedOrgIDs != nil && len(scopedOrgIDs) == 0 {
		return []*rbac.AuditLogEntry{}, nil
	}

	base := `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address, created_at
	         FROM rbac_audit_log WHERE actor_id = $1`
	args := []any{actorID}
	idx := 2

	if scopedOrgIDs != nil {
		base += fmt.Sprintf(" AND org_id = ANY($%d)", idx)
		args = append(args, scopedOrgIDs)
		idx++
	}
	base += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, base, args...)
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
		var actorID, resourceID, orgID sql.NullString
		var oldValue, newValue []byte

		if err := rows.Scan(
			&entry.ID, &actorID, &entry.ActorExternalID, &entry.Action, &entry.ResourceType,
			&resourceID, &entry.ResourceName, &orgID, &oldValue, &newValue, &entry.IPAddress,
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
		if orgID.Valid {
			entry.OrgID = &orgID.String
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
