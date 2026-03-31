package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"privacy-proxy/internal/rbac"
)

// UpdateApprovalRequestStatus updates the status within a transaction.
func (t *Tx) UpdateApprovalRequestStatus(ctx context.Context, id string, status rbac.ApprovalRequestStatus, resolvedAt *time.Time) error {
	query := `UPDATE approval_requests SET status = $2, resolved_at = $3 WHERE id = $1`
	_, err := t.tx.ExecContext(ctx, query, id, status, resolvedAt)
	if err != nil {
		return fmt.Errorf("failed to update approval request status: %w", err)
	}
	return nil
}

// RecordApprovalDecision inserts a decision within a transaction.
func (t *Tx) RecordApprovalDecision(ctx context.Context, decision *rbac.ApprovalDecision) error {
	query := `INSERT INTO approval_decisions (id, request_id, approver_id, decision, reason)
	          VALUES ($1, $2, $3, $4, $5)
	          RETURNING decided_at`

	return t.tx.QueryRowContext(ctx, query,
		decision.ID, decision.RequestID, decision.ApproverID, decision.Decision, decision.Reason,
	).Scan(&decision.DecidedAt)
}

// LockApprovalRequest loads an approval request within a transaction with FOR UPDATE.
func (t *Tx) LockApprovalRequest(ctx context.Context, id string) (*rbac.ApprovalRequest, error) {
	query := `SELECT id, org_id, requester_id, change_type, target_resource_id, target_resource_type, payload, status, approvals_needed, created_at, resolved_at, escalated_at
	          FROM approval_requests WHERE id = $1 FOR UPDATE`

	var req rbac.ApprovalRequest
	var payload []byte
	var resolvedAt, escalatedAt sql.NullTime

	err := t.tx.QueryRowContext(ctx, query, id).Scan(
		&req.ID, &req.OrgID, &req.RequesterID, &req.ChangeType, &req.TargetResourceID, &req.TargetResourceType, &payload, &req.Status, &req.ApprovalsNeeded, &req.CreatedAt, &resolvedAt, &escalatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lock approval request: %w", err)
	}

	req.Payload = json.RawMessage(payload)
	if resolvedAt.Valid {
		req.ResolvedAt = &resolvedAt.Time
	}
	if escalatedAt.Valid {
		req.EscalatedAt = &escalatedAt.Time
	}

	return &req, nil
}

// CountApprovals counts the number of 'approve' decisions for a request.
func (t *Tx) CountApprovals(ctx context.Context, requestID string) (int, error) {
	var count int
	err := t.tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM approval_decisions WHERE request_id = $1 AND decision = 'approve'`, requestID).Scan(&count)
	return count, err
}
