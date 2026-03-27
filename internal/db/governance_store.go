package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"privacy-proxy/internal/rbac"
)

// ApprovalRequestFilter holds optional filters for listing requests.
type ApprovalRequestFilter struct {
	Status      *rbac.ApprovalRequestStatus
	RequesterID *string
	ChangeType  *string
}

// ListApprovalRequests fetches approval requests with optional filtering and pagination.
func (d *DB) ListApprovalRequests(ctx context.Context, orgID string, limit, offset int, filter ApprovalRequestFilter) ([]*rbac.ApprovalRequest, int, error) {
	baseQuery := `FROM approval_requests WHERE org_id = $1`
	args := []any{orgID}
	argIdx := 2

	if filter.Status != nil {
		baseQuery += fmt.Sprintf(` AND status = $%d`, argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.RequesterID != nil {
		baseQuery += fmt.Sprintf(` AND requester_id = $%d`, argIdx)
		args = append(args, *filter.RequesterID)
		argIdx++
	}
	if filter.ChangeType != nil {
		baseQuery += fmt.Sprintf(` AND change_type = $%d`, argIdx)
		args = append(args, *filter.ChangeType)
		argIdx++
	}

	countQuery := `SELECT count(*) ` + baseQuery
	var total int
	if err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count requests: %w", err)
	}

	query := `SELECT id, org_id, requester_id, change_type, target_resource_id, target_resource_type, payload, status, approvals_needed, created_at, resolved_at ` +
		baseQuery + fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d OFFSET %d`, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list requests: %w", err)
	}
	defer rows.Close()

	var reqs []*rbac.ApprovalRequest
	for rows.Next() {
		var req rbac.ApprovalRequest
		var payload []byte
		var resolvedAt sql.NullTime
		if err := rows.Scan(&req.ID, &req.OrgID, &req.RequesterID, &req.ChangeType, &req.TargetResourceID, &req.TargetResourceType, &payload, &req.Status, &req.ApprovalsNeeded, &req.CreatedAt, &resolvedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan request: %w", err)
		}
		req.Payload = json.RawMessage(payload)
		if resolvedAt.Valid {
			req.ResolvedAt = &resolvedAt.Time
		}
		reqs = append(reqs, &req)
	}
	return reqs, total, nil
}

// CreateApprovalRequest inserts a new approval request into the database.
func (d *DB) CreateApprovalRequest(ctx context.Context, req *rbac.ApprovalRequest) error {
	query := `INSERT INTO approval_requests (id, org_id, requester_id, change_type, target_resource_id, target_resource_type, payload, status, approvals_needed)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING created_at`

	payload, err := json.Marshal(req.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	return d.conn.QueryRowContext(ctx, query,
		req.ID, req.OrgID, req.RequesterID, req.ChangeType, req.TargetResourceID, req.TargetResourceType, payload, req.Status, req.ApprovalsNeeded,
	).Scan(&req.CreatedAt)
}

// GetApprovalRequest fetches an approval request by ID.
func (d *DB) GetApprovalRequest(ctx context.Context, id string) (*rbac.ApprovalRequest, error) {
	query := `SELECT id, org_id, requester_id, change_type, target_resource_id, target_resource_type, payload, status, approvals_needed, created_at, resolved_at
	          FROM approval_requests WHERE id = $1`

	var req rbac.ApprovalRequest
	var payload []byte
	var resolvedAt sql.NullTime

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&req.ID, &req.OrgID, &req.RequesterID, &req.ChangeType, &req.TargetResourceID, &req.TargetResourceType, &payload, &req.Status, &req.ApprovalsNeeded, &req.CreatedAt, &resolvedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get approval request: %w", err)
	}

	req.Payload = json.RawMessage(payload)
	if resolvedAt.Valid {
		req.ResolvedAt = &resolvedAt.Time
	}

	return &req, nil
}

// ListPendingApprovalRequests fetches all pending requests for a specific organization.
func (d *DB) ListPendingApprovalRequests(ctx context.Context, orgID string) ([]*rbac.ApprovalRequest, error) {
	query := `SELECT id, org_id, requester_id, change_type, target_resource_id, target_resource_type, payload, status, approvals_needed, created_at, resolved_at
	          FROM approval_requests WHERE org_id = $1 AND status = 'pending'
			  ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending requests: %w", err)
	}
	defer rows.Close()

	var requests []*rbac.ApprovalRequest
	for rows.Next() {
		var req rbac.ApprovalRequest
		var payload []byte
		var resolvedAt sql.NullTime

		if err := rows.Scan(
			&req.ID, &req.OrgID, &req.RequesterID, &req.ChangeType, &req.TargetResourceID, &req.TargetResourceType, &payload, &req.Status, &req.ApprovalsNeeded, &req.CreatedAt, &resolvedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}

		req.Payload = json.RawMessage(payload)
		if resolvedAt.Valid {
			req.ResolvedAt = &resolvedAt.Time
		}
		requests = append(requests, &req)
	}

	return requests, rows.Err()
}


// GetApprovalDecisions returns all decisions for a specific request.
func (d *DB) GetApprovalDecisions(ctx context.Context, requestID string) ([]*rbac.ApprovalDecision, error) {
	query := `SELECT id, request_id, approver_id, decision, reason, decided_at
	          FROM approval_decisions WHERE request_id = $1
	          ORDER BY decided_at ASC`

	rows, err := d.conn.QueryContext(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to list approval decisions: %w", err)
	}
	defer rows.Close()

	var decisions []*rbac.ApprovalDecision
	for rows.Next() {
		var dec rbac.ApprovalDecision
		if err := rows.Scan(
			&dec.ID, &dec.RequestID, &dec.ApproverID, &dec.Decision, &dec.Reason, &dec.DecidedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan decision: %w", err)
		}
		decisions = append(decisions, &dec)
	}
	return decisions, rows.Err()
}

// CreateApprovalNotification inserts a notification record.
func (d *DB) CreateApprovalNotification(ctx context.Context, notif *rbac.ApprovalNotification) error {
	query := `INSERT INTO approval_notifications (id, request_id, approver_id, channel)
	          VALUES ($1, $2, $3, $4)
	          RETURNING sent_at`

	return d.conn.QueryRowContext(ctx, query,
		notif.ID, notif.RequestID, notif.ApproverID, notif.Channel,
	).Scan(&notif.SentAt)
}

// --- Governance Approver Groups ---

// AddGovernanceApproverGroup designates a group as an approver group for governance requests.
func (d *DB) AddGovernanceApproverGroup(ctx context.Context, orgID, groupID string) error {
	query := `INSERT INTO governance_approver_groups (org_id, group_id)
	          VALUES ($1, $2)
	          ON CONFLICT (org_id, group_id) DO NOTHING`

	_, err := d.conn.ExecContext(ctx, query, orgID, groupID)
	if err != nil {
		return fmt.Errorf("failed to add governance approver group: %w", err)
	}
	return nil
}

// RemoveGovernanceApproverGroup removes a group from the approver groups for an org.
func (d *DB) RemoveGovernanceApproverGroup(ctx context.Context, orgID, groupID string) error {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM governance_approver_groups WHERE org_id = $1 AND group_id = $2`,
		orgID, groupID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove governance approver group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListGovernanceApproverGroups returns all designated approver groups for an org,
// joined with the group name and slug.
func (d *DB) ListGovernanceApproverGroups(ctx context.Context, orgID string) ([]*rbac.GovernanceApproverGroup, error) {
	query := `SELECT gag.id, gag.org_id, gag.group_id, g.name, g.slug, gag.created_at
	          FROM governance_approver_groups gag
	          JOIN groups g ON g.id = gag.group_id
	          WHERE gag.org_id = $1
	          ORDER BY g.name ASC`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list governance approver groups: %w", err)
	}
	defer rows.Close()

	var groups []*rbac.GovernanceApproverGroup
	for rows.Next() {
		var g rbac.GovernanceApproverGroup
		if err := rows.Scan(&g.ID, &g.OrgID, &g.GroupID, &g.GroupName, &g.GroupSlug, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan governance approver group: %w", err)
		}
		groups = append(groups, &g)
	}
	return groups, rows.Err()
}

// IsGovernanceApprover checks if a user is eligible to approve governance requests for an org.
// If no approver groups are configured, returns true for any org admin (backward compatible).
// If approver groups are configured, returns true only if the user is a member of at least one.
func (d *DB) IsGovernanceApprover(ctx context.Context, orgID, userID string) (bool, error) {
	// First check if any approver groups are configured for this org.
	var count int
	err := d.conn.QueryRowContext(ctx,
		`SELECT count(*) FROM governance_approver_groups WHERE org_id = $1`,
		orgID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to count approver groups: %w", err)
	}

	if count == 0 {
		// No approver groups configured: fall back to "any org admin can approve".
		var isAdmin bool
		err := d.conn.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1
				FROM user_memberships m
				JOIN groups g ON g.id = m.group_id
				JOIN group_access ga ON ga.group_id = m.group_id
				WHERE m.user_id = $1
				  AND g.org_id = $2
				  AND 'admin' = ANY(ga.claims)
				  AND (m.expires_at IS NULL OR m.expires_at > NOW())
			)`, userID, orgID,
		).Scan(&isAdmin)
		if err != nil {
			return false, fmt.Errorf("failed to check admin claim: %w", err)
		}
		return isAdmin, nil
	}

	// Approver groups are configured: check if user is a member of any of them.
	var isMember bool
	err = d.conn.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM governance_approver_groups gag
			JOIN user_memberships m ON m.group_id = gag.group_id
			WHERE gag.org_id = $1
			  AND m.user_id = $2
			  AND (m.expires_at IS NULL OR m.expires_at > NOW())
		)`, orgID, userID,
	).Scan(&isMember)
	if err != nil {
		return false, fmt.Errorf("failed to check approver group membership: %w", err)
	}
	return isMember, nil
}
