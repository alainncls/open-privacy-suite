package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"privacy-proxy/internal/disclosure"
)

// Ensure DB implements disclosure.Store
var _ disclosure.Store = (*DB)(nil)

// Request operations

func (d *DB) CreateDisclosureRequest(ctx context.Context, req *disclosure.Request) error {
	query := `INSERT INTO disclosure_requests
		(id, requester_user_id, requester_did, target_user_id, org_id, scope, reason, legal_basis, status, requested_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	scope, err := json.Marshal(req.Scope)
	if err != nil {
		return fmt.Errorf("failed to marshal scope: %w", err)
	}

	var requesterDID *string
	if req.RequesterDID != "" {
		requesterDID = &req.RequesterDID
	}

	_, err = d.conn.ExecContext(ctx, query,
		req.ID, req.RequesterUserID, requesterDID, req.TargetUserID, req.OrgID, scope,
		req.Reason, req.LegalBasis, req.Status, req.RequestedAt, req.ExpiresAt,
	)
	return err
}

func (d *DB) GetDisclosureRequest(ctx context.Context, id string) (*disclosure.Request, error) {
	query := `SELECT id, requester_user_id, requester_did, target_user_id, org_id, scope, reason, legal_basis,
		status, requested_at, expires_at, decided_at, decided_by_user_id, decision_reason
		FROM disclosure_requests WHERE id = $1`

	req := &disclosure.Request{}
	var requesterID, requesterDID, decidedByID sql.NullString
	var expiresAt, decidedAt sql.NullTime
	var legalBasis, decisionReason sql.NullString
	var scope []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&req.ID, &requesterID, &requesterDID, &req.TargetUserID, &req.OrgID, &scope,
		&req.Reason, &legalBasis, &req.Status, &req.RequestedAt,
		&expiresAt, &decidedAt, &decidedByID, &decisionReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosure request: %w", err)
	}

	if requesterID.Valid {
		req.RequesterUserID = &requesterID.String
	}
	if requesterDID.Valid {
		req.RequesterDID = requesterDID.String
	}
	if decidedByID.Valid {
		req.DecidedByUserID = &decidedByID.String
	}
	if expiresAt.Valid {
		req.ExpiresAt = &expiresAt.Time
	}
	if decidedAt.Valid {
		req.DecidedAt = &decidedAt.Time
	}
	if legalBasis.Valid {
		req.LegalBasis = legalBasis.String
	}
	if decisionReason.Valid {
		req.DecisionReason = decisionReason.String
	}

	if err := json.Unmarshal(scope, &req.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
	}

	return req, nil
}

func (d *DB) GetDisclosureRequestWithDetails(ctx context.Context, id string) (*disclosure.RequestWithDetails, error) {
	query := `SELECT dr.id, dr.requester_user_id, dr.target_user_id, dr.org_id, dr.scope, dr.reason,
		dr.legal_basis, dr.status, dr.requested_at, dr.expires_at, dr.decided_at, dr.decided_by_user_id, dr.decision_reason,
		COALESCE(ru.external_id, ''), COALESCE(tu.external_id, ''), COALESCE(du.external_id, ''),
		(SELECT id FROM disclosure_grants WHERE request_id = dr.id AND revoked_at IS NULL AND expires_at > NOW() LIMIT 1)
		FROM disclosure_requests dr
		LEFT JOIN users ru ON dr.requester_user_id = ru.id
		LEFT JOIN users tu ON dr.target_user_id = tu.id
		LEFT JOIN users du ON dr.decided_by_user_id = du.id
		WHERE dr.id = $1`

	req := &disclosure.Request{}
	details := &disclosure.RequestWithDetails{Request: req}
	var requesterID, decidedByID sql.NullString
	var expiresAt, decidedAt sql.NullTime
	var legalBasis, decisionReason sql.NullString
	var activeGrantID sql.NullString
	var scope []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&req.ID, &requesterID, &req.TargetUserID, &req.OrgID, &scope,
		&req.Reason, &legalBasis, &req.Status, &req.RequestedAt,
		&expiresAt, &decidedAt, &decidedByID, &decisionReason,
		&details.RequesterDID, &details.TargetDID, &details.DecidedByDID, &activeGrantID,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosure request with details: %w", err)
	}

	if requesterID.Valid {
		req.RequesterUserID = &requesterID.String
	}
	if decidedByID.Valid {
		req.DecidedByUserID = &decidedByID.String
	}
	if expiresAt.Valid {
		req.ExpiresAt = &expiresAt.Time
	}
	if decidedAt.Valid {
		req.DecidedAt = &decidedAt.Time
	}
	if legalBasis.Valid {
		req.LegalBasis = legalBasis.String
	}
	if decisionReason.Valid {
		req.DecisionReason = decisionReason.String
	}
	if activeGrantID.Valid {
		details.ActiveGrantID = &activeGrantID.String
	}

	if err := json.Unmarshal(scope, &req.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
	}

	return details, nil
}

func (d *DB) UpdateDisclosureRequestStatus(ctx context.Context, id string, status disclosure.RequestStatus, decidedByUserID *string, reason string) error {
	query := `UPDATE disclosure_requests
		SET status = $2, decided_at = NOW(), decided_by_user_id = $3, decision_reason = $4
		WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query, id, status, decidedByUserID, reason)
	return err
}

func (d *DB) ListDisclosureRequestsByTarget(ctx context.Context, targetUserID string, status *disclosure.RequestStatus) ([]*disclosure.Request, error) {
	query := `SELECT id, requester_user_id, requester_did, target_user_id, org_id, scope, reason, legal_basis,
		status, requested_at, expires_at, decided_at, decided_by_user_id, decision_reason
		FROM disclosure_requests WHERE target_user_id = $1`
	args := []any{targetUserID}

	if status != nil {
		query += ` AND status = $2`
		args = append(args, *status)
	}
	query += ` ORDER BY requested_at DESC`

	return d.scanDisclosureRequests(ctx, query, args...)
}

func (d *DB) ListDisclosureRequestsByRequester(ctx context.Context, requesterUserID string) ([]*disclosure.Request, error) {
	query := `SELECT id, requester_user_id, requester_did, target_user_id, org_id, scope, reason, legal_basis,
		status, requested_at, expires_at, decided_at, decided_by_user_id, decision_reason
		FROM disclosure_requests WHERE requester_user_id = $1 ORDER BY requested_at DESC`

	return d.scanDisclosureRequests(ctx, query, requesterUserID)
}

func (d *DB) ListDisclosureRequestsByOrg(ctx context.Context, orgID string, status *disclosure.RequestStatus) ([]*disclosure.Request, error) {
	query := `SELECT id, requester_user_id, requester_did, target_user_id, org_id, scope, reason, legal_basis,
		status, requested_at, expires_at, decided_at, decided_by_user_id, decision_reason
		FROM disclosure_requests WHERE org_id = $1`
	args := []any{orgID}

	if status != nil {
		query += ` AND status = $2`
		args = append(args, *status)
	}
	query += ` ORDER BY requested_at DESC`

	return d.scanDisclosureRequests(ctx, query, args...)
}

func (d *DB) ListPendingDisclosureRequestsForUser(ctx context.Context, targetUserID string) ([]*disclosure.RequestWithDetails, error) {
	query := `SELECT dr.id, dr.requester_user_id, dr.target_user_id, dr.org_id, dr.scope, dr.reason,
		dr.legal_basis, dr.status, dr.requested_at, dr.expires_at, dr.decided_at, dr.decided_by_user_id, dr.decision_reason,
		COALESCE(ru.external_id, ''), COALESCE(tu.external_id, '')
		FROM disclosure_requests dr
		LEFT JOIN users ru ON dr.requester_user_id = ru.id
		LEFT JOIN users tu ON dr.target_user_id = tu.id
		WHERE dr.target_user_id = $1 AND dr.status = 'pending'
		AND (dr.expires_at IS NULL OR dr.expires_at > NOW())
		ORDER BY dr.requested_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending requests: %w", err)
	}
	defer rows.Close()

	var results []*disclosure.RequestWithDetails
	for rows.Next() {
		req := &disclosure.Request{}
		details := &disclosure.RequestWithDetails{Request: req}
		var requesterID, decidedByID sql.NullString
		var expiresAt, decidedAt sql.NullTime
		var legalBasis, decisionReason sql.NullString
		var scope []byte

		if err := rows.Scan(
			&req.ID, &requesterID, &req.TargetUserID, &req.OrgID, &scope,
			&req.Reason, &legalBasis, &req.Status, &req.RequestedAt,
			&expiresAt, &decidedAt, &decidedByID, &decisionReason,
			&details.RequesterDID, &details.TargetDID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}

		if requesterID.Valid {
			req.RequesterUserID = &requesterID.String
		}
		if decidedByID.Valid {
			req.DecidedByUserID = &decidedByID.String
		}
		if expiresAt.Valid {
			req.ExpiresAt = &expiresAt.Time
		}
		if decidedAt.Valid {
			req.DecidedAt = &decidedAt.Time
		}
		if legalBasis.Valid {
			req.LegalBasis = legalBasis.String
		}
		if decisionReason.Valid {
			req.DecisionReason = decisionReason.String
		}

		if err := json.Unmarshal(scope, &req.Scope); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
		}

		results = append(results, details)
	}

	return results, nil
}

func (d *DB) ExpirePendingDisclosureRequests(ctx context.Context) (int64, error) {
	query := `UPDATE disclosure_requests
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < NOW()`

	result, err := d.conn.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (d *DB) scanDisclosureRequests(ctx context.Context, query string, args ...any) ([]*disclosure.Request, error) {
	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query disclosure requests: %w", err)
	}
	defer rows.Close()

	var requests []*disclosure.Request
	for rows.Next() {
		req := &disclosure.Request{}
		var requesterID, requesterDID, decidedByID sql.NullString
		var expiresAt, decidedAt sql.NullTime
		var legalBasis, decisionReason sql.NullString
		var scope []byte

		if err := rows.Scan(
			&req.ID, &requesterID, &requesterDID, &req.TargetUserID, &req.OrgID, &scope,
			&req.Reason, &legalBasis, &req.Status, &req.RequestedAt,
			&expiresAt, &decidedAt, &decidedByID, &decisionReason,
		); err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}

		if requesterID.Valid {
			req.RequesterUserID = &requesterID.String
		}
		if requesterDID.Valid {
			req.RequesterDID = requesterDID.String
		}
		if decidedByID.Valid {
			req.DecidedByUserID = &decidedByID.String
		}
		if expiresAt.Valid {
			req.ExpiresAt = &expiresAt.Time
		}
		if decidedAt.Valid {
			req.DecidedAt = &decidedAt.Time
		}
		if legalBasis.Valid {
			req.LegalBasis = legalBasis.String
		}
		if decisionReason.Valid {
			req.DecisionReason = decisionReason.String
		}

		if err := json.Unmarshal(scope, &req.Scope); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
		}

		requests = append(requests, req)
	}

	return requests, nil
}

// Grant operations

func (d *DB) CreateDisclosureGrant(ctx context.Context, grant *disclosure.Grant) error {
	query := `INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	scope, err := json.Marshal(grant.Scope)
	if err != nil {
		return fmt.Errorf("failed to marshal scope: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query,
		grant.ID, grant.RequestID, grant.GrantTokenHash, scope, grant.GrantedAt, grant.ExpiresAt,
	)
	return err
}

func (d *DB) GetDisclosureGrant(ctx context.Context, id string) (*disclosure.Grant, error) {
	query := `SELECT id, request_id, grant_token_hash, scope, granted_at, expires_at, revoked_at, revoked_reason
		FROM disclosure_grants WHERE id = $1`

	grant := &disclosure.Grant{}
	var revokedAt sql.NullTime
	var revokedReason sql.NullString
	var scope []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&grant.ID, &grant.RequestID, &grant.GrantTokenHash, &scope,
		&grant.GrantedAt, &grant.ExpiresAt, &revokedAt, &revokedReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosure grant: %w", err)
	}

	if revokedAt.Valid {
		grant.RevokedAt = &revokedAt.Time
	}
	if revokedReason.Valid {
		grant.RevokedReason = revokedReason.String
	}

	if err := json.Unmarshal(scope, &grant.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
	}

	return grant, nil
}

func (d *DB) GetDisclosureGrantByToken(ctx context.Context, tokenHash string) (*disclosure.Grant, error) {
	query := `SELECT id, request_id, grant_token_hash, scope, granted_at, expires_at, revoked_at, revoked_reason
		FROM disclosure_grants WHERE grant_token_hash = $1`

	grant := &disclosure.Grant{}
	var revokedAt sql.NullTime
	var revokedReason sql.NullString
	var scope []byte

	err := d.conn.QueryRowContext(ctx, query, tokenHash).Scan(
		&grant.ID, &grant.RequestID, &grant.GrantTokenHash, &scope,
		&grant.GrantedAt, &grant.ExpiresAt, &revokedAt, &revokedReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosure grant by token: %w", err)
	}

	if revokedAt.Valid {
		grant.RevokedAt = &revokedAt.Time
	}
	if revokedReason.Valid {
		grant.RevokedReason = revokedReason.String
	}

	if err := json.Unmarshal(scope, &grant.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
	}

	return grant, nil
}

func (d *DB) GetDisclosureGrantWithRequest(ctx context.Context, id string) (*disclosure.GrantWithRequest, error) {
	grant, err := d.GetDisclosureGrant(ctx, id)
	if err != nil || grant == nil {
		return nil, err
	}

	req, err := d.GetDisclosureRequest(ctx, grant.RequestID)
	if err != nil {
		return nil, err
	}

	return &disclosure.GrantWithRequest{Grant: grant, Request: req}, nil
}

func (d *DB) GetActiveDisclosureGrantForRequest(ctx context.Context, requestID string) (*disclosure.Grant, error) {
	query := `SELECT id, request_id, grant_token_hash, scope, granted_at, expires_at, revoked_at, revoked_reason
		FROM disclosure_grants
		WHERE request_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		LIMIT 1`

	grant := &disclosure.Grant{}
	var revokedAt sql.NullTime
	var revokedReason sql.NullString
	var scope []byte

	err := d.conn.QueryRowContext(ctx, query, requestID).Scan(
		&grant.ID, &grant.RequestID, &grant.GrantTokenHash, &scope,
		&grant.GrantedAt, &grant.ExpiresAt, &revokedAt, &revokedReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active grant: %w", err)
	}

	if revokedAt.Valid {
		grant.RevokedAt = &revokedAt.Time
	}
	if revokedReason.Valid {
		grant.RevokedReason = revokedReason.String
	}

	if err := json.Unmarshal(scope, &grant.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scope: %w", err)
	}

	return grant, nil
}

func (d *DB) RevokeDisclosureGrant(ctx context.Context, id string, reason string) error {
	query := `UPDATE disclosure_grants SET revoked_at = NOW(), revoked_reason = $2 WHERE id = $1`
	_, err := d.conn.ExecContext(ctx, query, id, reason)
	return err
}

func (d *DB) ListActiveDisclosureGrantsForTarget(ctx context.Context, targetUserID string) ([]*disclosure.GrantWithRequest, error) {
	query := `SELECT g.id, g.request_id, g.grant_token_hash, g.scope, g.granted_at, g.expires_at, g.revoked_at, g.revoked_reason,
		r.id, r.requester_user_id, r.target_user_id, r.org_id, r.scope, r.reason, r.legal_basis,
		r.status, r.requested_at, r.expires_at, r.decided_at, r.decided_by_user_id, r.decision_reason
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		WHERE r.target_user_id = $1 AND g.revoked_at IS NULL AND g.expires_at > NOW()
		ORDER BY g.granted_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active grants: %w", err)
	}
	defer rows.Close()

	var results []*disclosure.GrantWithRequest
	for rows.Next() {
		grant := &disclosure.Grant{}
		req := &disclosure.Request{}

		var gRevokedAt sql.NullTime
		var gRevokedReason sql.NullString
		var gScope []byte

		var rRequesterID, rDecidedByID sql.NullString
		var rExpiresAt, rDecidedAt sql.NullTime
		var rLegalBasis, rDecisionReason sql.NullString
		var rScope []byte

		if err := rows.Scan(
			&grant.ID, &grant.RequestID, &grant.GrantTokenHash, &gScope,
			&grant.GrantedAt, &grant.ExpiresAt, &gRevokedAt, &gRevokedReason,
			&req.ID, &rRequesterID, &req.TargetUserID, &req.OrgID, &rScope,
			&req.Reason, &rLegalBasis, &req.Status, &req.RequestedAt,
			&rExpiresAt, &rDecidedAt, &rDecidedByID, &rDecisionReason,
		); err != nil {
			return nil, fmt.Errorf("failed to scan grant: %w", err)
		}

		if gRevokedAt.Valid {
			grant.RevokedAt = &gRevokedAt.Time
		}
		if gRevokedReason.Valid {
			grant.RevokedReason = gRevokedReason.String
		}
		if err := json.Unmarshal(gScope, &grant.Scope); err != nil {
			return nil, fmt.Errorf("failed to unmarshal grant scope: %w", err)
		}

		if rRequesterID.Valid {
			req.RequesterUserID = &rRequesterID.String
		}
		if rDecidedByID.Valid {
			req.DecidedByUserID = &rDecidedByID.String
		}
		if rExpiresAt.Valid {
			req.ExpiresAt = &rExpiresAt.Time
		}
		if rDecidedAt.Valid {
			req.DecidedAt = &rDecidedAt.Time
		}
		if rLegalBasis.Valid {
			req.LegalBasis = rLegalBasis.String
		}
		if rDecisionReason.Valid {
			req.DecisionReason = rDecisionReason.String
		}
		if err := json.Unmarshal(rScope, &req.Scope); err != nil {
			return nil, fmt.Errorf("failed to unmarshal request scope: %w", err)
		}

		results = append(results, &disclosure.GrantWithRequest{Grant: grant, Request: req})
	}

	return results, nil
}

// GetActiveGrantByRequesterDID finds an active grant where the requester_did matches.
// This is used by block explorer to check if a DID has access to a specific user's data.
func (d *DB) GetActiveGrantByRequesterDID(ctx context.Context, requesterDID, targetUserExternalID string) (*disclosure.GrantWithRequest, error) {
	query := `SELECT g.id, g.request_id, g.grant_token_hash, g.scope, g.granted_at, g.expires_at, g.revoked_at, g.revoked_reason,
		r.id, r.requester_user_id, r.requester_did, r.target_user_id, r.org_id, r.scope, r.reason, r.legal_basis,
		r.status, r.requested_at, r.expires_at, r.decided_at, r.decided_by_user_id, r.decision_reason
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		JOIN users u ON r.target_user_id = u.id
		WHERE r.requester_did = $1
		AND u.external_id = $2
		AND g.revoked_at IS NULL
		AND g.expires_at > NOW()
		ORDER BY g.granted_at DESC
		LIMIT 1`

	grant := &disclosure.Grant{}
	req := &disclosure.Request{}

	var gRevokedAt sql.NullTime
	var gRevokedReason sql.NullString
	var gScope []byte

	var rRequesterID, rRequesterDID, rDecidedByID sql.NullString
	var rExpiresAt, rDecidedAt sql.NullTime
	var rLegalBasis, rDecisionReason sql.NullString
	var rScope []byte

	err := d.conn.QueryRowContext(ctx, query, requesterDID, targetUserExternalID).Scan(
		&grant.ID, &grant.RequestID, &grant.GrantTokenHash, &gScope,
		&grant.GrantedAt, &grant.ExpiresAt, &gRevokedAt, &gRevokedReason,
		&req.ID, &rRequesterID, &rRequesterDID, &req.TargetUserID, &req.OrgID, &rScope,
		&req.Reason, &rLegalBasis, &req.Status, &req.RequestedAt,
		&rExpiresAt, &rDecidedAt, &rDecidedByID, &rDecisionReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active grant by requester DID: %w", err)
	}

	if gRevokedAt.Valid {
		grant.RevokedAt = &gRevokedAt.Time
	}
	if gRevokedReason.Valid {
		grant.RevokedReason = gRevokedReason.String
	}
	if err := json.Unmarshal(gScope, &grant.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal grant scope: %w", err)
	}

	if rRequesterID.Valid {
		req.RequesterUserID = &rRequesterID.String
	}
	if rRequesterDID.Valid {
		req.RequesterDID = rRequesterDID.String
	}
	if rDecidedByID.Valid {
		req.DecidedByUserID = &rDecidedByID.String
	}
	if rExpiresAt.Valid {
		req.ExpiresAt = &rExpiresAt.Time
	}
	if rDecidedAt.Valid {
		req.DecidedAt = &rDecidedAt.Time
	}
	if rLegalBasis.Valid {
		req.LegalBasis = rLegalBasis.String
	}
	if rDecisionReason.Valid {
		req.DecisionReason = rDecisionReason.String
	}
	if err := json.Unmarshal(rScope, &req.Scope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request scope: %w", err)
	}

	return &disclosure.GrantWithRequest{Grant: grant, Request: req}, nil
}

// Event operations

func (d *DB) CreateDisclosureEvent(ctx context.Context, event *disclosure.Event) error {
	query := `INSERT INTO disclosure_events
		(grant_id, viewer_user_id, action, resource_type, data_summary, viewer_ip, accessed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`

	var dataSummary []byte
	var err error
	if event.DataSummary != nil {
		dataSummary, err = json.Marshal(event.DataSummary)
		if err != nil {
			return fmt.Errorf("failed to marshal data summary: %w", err)
		}
	}

	return d.conn.QueryRowContext(ctx, query,
		event.GrantID, event.ViewerUserID, event.Action, event.ResourceType,
		dataSummary, event.ViewerIP, event.AccessedAt,
	).Scan(&event.ID)
}

func (d *DB) ListDisclosureEventsByGrant(ctx context.Context, grantID string, limit, offset int) ([]*disclosure.Event, error) {
	query := `SELECT id, grant_id, viewer_user_id, action, resource_type, data_summary, viewer_ip, accessed_at
		FROM disclosure_events WHERE grant_id = $1 ORDER BY accessed_at DESC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, grantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}
	defer rows.Close()

	var events []*disclosure.Event
	for rows.Next() {
		event := &disclosure.Event{}
		var viewerUserID sql.NullString
		var dataSummary []byte

		if err := rows.Scan(
			&event.ID, &event.GrantID, &viewerUserID, &event.Action,
			&event.ResourceType, &dataSummary, &event.ViewerIP, &event.AccessedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if viewerUserID.Valid {
			event.ViewerUserID = &viewerUserID.String
		}
		if len(dataSummary) > 0 {
			event.DataSummary = &disclosure.DataSummary{}
			if err := json.Unmarshal(dataSummary, event.DataSummary); err != nil {
				return nil, fmt.Errorf("failed to unmarshal data summary: %w", err)
			}
		}

		events = append(events, event)
	}

	return events, nil
}

func (d *DB) GetDisclosureEventStats(ctx context.Context, grantID string) (map[disclosure.EventAction]int, error) {
	query := `SELECT action, COUNT(*) FROM disclosure_events WHERE grant_id = $1 GROUP BY action`

	rows, err := d.conn.QueryContext(ctx, query, grantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get event stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[disclosure.EventAction]int)
	for rows.Next() {
		var action disclosure.EventAction
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			return nil, fmt.Errorf("failed to scan stat: %w", err)
		}
		stats[action] = count
	}

	return stats, nil
}

// Report operations

func (d *DB) CreateDisclosureReport(ctx context.Context, report *disclosure.Report) error {
	query := `INSERT INTO disclosure_reports
		(id, grant_id, report_type, report_data, generated_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	reportData, err := json.Marshal(report.ReportData)
	if err != nil {
		return fmt.Errorf("failed to marshal report data: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query,
		report.ID, report.GrantID, report.ReportType, reportData, report.GeneratedAt, report.ExpiresAt,
	)
	return err
}

func (d *DB) GetDisclosureReport(ctx context.Context, id string) (*disclosure.Report, error) {
	query := `SELECT id, grant_id, report_type, report_data, generated_at, expires_at
		FROM disclosure_reports WHERE id = $1`

	report := &disclosure.Report{}
	var reportData []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&report.ID, &report.GrantID, &report.ReportType, &reportData,
		&report.GeneratedAt, &report.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	if err := json.Unmarshal(reportData, &report.ReportData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report data: %w", err)
	}

	return report, nil
}

func (d *DB) GetDisclosureReportByGrantAndType(ctx context.Context, grantID string, reportType disclosure.ReportType) (*disclosure.Report, error) {
	query := `SELECT id, grant_id, report_type, report_data, generated_at, expires_at
		FROM disclosure_reports WHERE grant_id = $1 AND report_type = $2 AND expires_at > NOW()
		ORDER BY generated_at DESC LIMIT 1`

	report := &disclosure.Report{}
	var reportData []byte

	err := d.conn.QueryRowContext(ctx, query, grantID, reportType).Scan(
		&report.ID, &report.GrantID, &report.ReportType, &reportData,
		&report.GeneratedAt, &report.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	if err := json.Unmarshal(reportData, &report.ReportData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report data: %w", err)
	}

	return report, nil
}

func (d *DB) DeleteExpiredDisclosureReports(ctx context.Context) (int64, error) {
	query := `DELETE FROM disclosure_reports WHERE expires_at < NOW()`
	result, err := d.conn.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Activity data access

func (d *DB) GetDisclosureActivityLogs(ctx context.Context, userExternalID string, scope *disclosure.Scope, limit, offset int) ([]*disclosure.ActivityLogEntry, error) {
	query := `SELECT id, method, status_code, ip_address, created_at
		FROM access_logs WHERE external_id = $1`
	args := []any{userExternalID}
	argIdx := 2

	if scope != nil {
		if len(scope.Methods) > 0 {
			query += fmt.Sprintf(` AND method = ANY($%d)`, argIdx)
			args = append(args, scope.Methods)
			argIdx++
		}
		if scope.DateRange != nil {
			query += fmt.Sprintf(` AND created_at >= $%d AND created_at <= $%d`, argIdx, argIdx+1)
			args = append(args, scope.DateRange.Start, scope.DateRange.End)
			argIdx += 2
		}
	}

	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get activity logs: %w", err)
	}
	defer rows.Close()

	var logs []*disclosure.ActivityLogEntry
	for rows.Next() {
		log := &disclosure.ActivityLogEntry{}
		var ipAddress sql.NullString

		if err := rows.Scan(&log.ID, &log.Method, &log.StatusCode, &ipAddress, &log.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan log: %w", err)
		}

		if ipAddress.Valid {
			log.IPAddress = ipAddress.String
		}

		logs = append(logs, log)
	}

	return logs, nil
}

func (d *DB) GetDisclosureActivitySummary(ctx context.Context, userExternalID string, scope *disclosure.Scope) (*disclosure.ActivitySummary, error) {
	// Build the query with optional scope filtering
	whereClause := `WHERE external_id = $1`
	args := []any{userExternalID}
	argIdx := 2

	if scope != nil {
		if len(scope.Methods) > 0 {
			whereClause += fmt.Sprintf(` AND method = ANY($%d)`, argIdx)
			args = append(args, scope.Methods)
			argIdx++
		}
		if scope.DateRange != nil {
			whereClause += fmt.Sprintf(` AND created_at >= $%d AND created_at <= $%d`, argIdx, argIdx+1)
			args = append(args, scope.DateRange.Start, scope.DateRange.End)
			argIdx += 2
		}
	}

	// Get counts
	countQuery := fmt.Sprintf(`SELECT
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) as successful,
		COUNT(*) FILTER (WHERE status_code >= 400) as failed,
		COUNT(DISTINCT method) as unique_methods,
		MIN(created_at) as min_date,
		MAX(created_at) as max_date
		FROM access_logs %s`, whereClause)

	summary := &disclosure.ActivitySummary{
		MethodBreakdown: make(map[string]int),
		GeneratedAt:     time.Now(),
	}

	var minDate, maxDate sql.NullTime
	err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(
		&summary.TotalRequests, &summary.SuccessfulCount, &summary.FailedCount,
		&summary.UniqueMethodCount, &minDate, &maxDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get summary counts: %w", err)
	}

	if minDate.Valid && maxDate.Valid {
		summary.DateRange = disclosure.DateRange{Start: minDate.Time, End: maxDate.Time}
	}

	// Get method breakdown
	breakdownQuery := fmt.Sprintf(`SELECT method, COUNT(*) FROM access_logs %s GROUP BY method`, whereClause)
	rows, err := d.conn.QueryContext(ctx, breakdownQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get method breakdown: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var method string
		var count int
		if err := rows.Scan(&method, &count); err != nil {
			return nil, fmt.Errorf("failed to scan breakdown: %w", err)
		}
		summary.MethodBreakdown[method] = count
	}

	return summary, nil
}

// Implement the Store interface methods by wrapping the prefixed methods

func (d *DB) CreateRequest(ctx context.Context, req *disclosure.Request) error {
	return d.CreateDisclosureRequest(ctx, req)
}

func (d *DB) GetRequest(ctx context.Context, id string) (*disclosure.Request, error) {
	return d.GetDisclosureRequest(ctx, id)
}

func (d *DB) GetRequestWithDetails(ctx context.Context, id string) (*disclosure.RequestWithDetails, error) {
	return d.GetDisclosureRequestWithDetails(ctx, id)
}

func (d *DB) UpdateRequestStatus(ctx context.Context, id string, status disclosure.RequestStatus, decidedByUserID *string, reason string) error {
	return d.UpdateDisclosureRequestStatus(ctx, id, status, decidedByUserID, reason)
}

func (d *DB) ListRequestsByTarget(ctx context.Context, targetUserID string, status *disclosure.RequestStatus) ([]*disclosure.Request, error) {
	return d.ListDisclosureRequestsByTarget(ctx, targetUserID, status)
}

func (d *DB) ListRequestsByRequester(ctx context.Context, requesterUserID string) ([]*disclosure.Request, error) {
	return d.ListDisclosureRequestsByRequester(ctx, requesterUserID)
}

func (d *DB) ListRequestsByOrg(ctx context.Context, orgID string, status *disclosure.RequestStatus) ([]*disclosure.Request, error) {
	return d.ListDisclosureRequestsByOrg(ctx, orgID, status)
}

func (d *DB) ListPendingRequestsForUser(ctx context.Context, targetUserID string) ([]*disclosure.RequestWithDetails, error) {
	return d.ListPendingDisclosureRequestsForUser(ctx, targetUserID)
}

func (d *DB) ExpirePendingRequests(ctx context.Context) (int64, error) {
	return d.ExpirePendingDisclosureRequests(ctx)
}

func (d *DB) CreateGrant(ctx context.Context, grant *disclosure.Grant) error {
	return d.CreateDisclosureGrant(ctx, grant)
}

func (d *DB) GetGrant(ctx context.Context, id string) (*disclosure.Grant, error) {
	return d.GetDisclosureGrant(ctx, id)
}

func (d *DB) GetGrantByToken(ctx context.Context, tokenHash string) (*disclosure.Grant, error) {
	return d.GetDisclosureGrantByToken(ctx, tokenHash)
}

func (d *DB) GetGrantWithRequest(ctx context.Context, id string) (*disclosure.GrantWithRequest, error) {
	return d.GetDisclosureGrantWithRequest(ctx, id)
}

func (d *DB) GetActiveGrantForRequest(ctx context.Context, requestID string) (*disclosure.Grant, error) {
	return d.GetActiveDisclosureGrantForRequest(ctx, requestID)
}

func (d *DB) RevokeGrant(ctx context.Context, id string, reason string) error {
	return d.RevokeDisclosureGrant(ctx, id, reason)
}

func (d *DB) ListActiveGrantsForTarget(ctx context.Context, targetUserID string) ([]*disclosure.GrantWithRequest, error) {
	return d.ListActiveDisclosureGrantsForTarget(ctx, targetUserID)
}

func (d *DB) CreateEvent(ctx context.Context, event *disclosure.Event) error {
	return d.CreateDisclosureEvent(ctx, event)
}

func (d *DB) ListEventsByGrant(ctx context.Context, grantID string, limit, offset int) ([]*disclosure.Event, error) {
	return d.ListDisclosureEventsByGrant(ctx, grantID, limit, offset)
}

func (d *DB) GetEventStats(ctx context.Context, grantID string) (map[disclosure.EventAction]int, error) {
	return d.GetDisclosureEventStats(ctx, grantID)
}

func (d *DB) CreateReport(ctx context.Context, report *disclosure.Report) error {
	return d.CreateDisclosureReport(ctx, report)
}

func (d *DB) GetReport(ctx context.Context, id string) (*disclosure.Report, error) {
	return d.GetDisclosureReport(ctx, id)
}

func (d *DB) GetReportByGrantAndType(ctx context.Context, grantID string, reportType disclosure.ReportType) (*disclosure.Report, error) {
	return d.GetDisclosureReportByGrantAndType(ctx, grantID, reportType)
}

func (d *DB) DeleteExpiredReports(ctx context.Context) (int64, error) {
	return d.DeleteExpiredDisclosureReports(ctx)
}

func (d *DB) GetActivityLogs(ctx context.Context, userExternalID string, scope *disclosure.Scope, limit, offset int) ([]*disclosure.ActivityLogEntry, error) {
	return d.GetDisclosureActivityLogs(ctx, userExternalID, scope, limit, offset)
}

func (d *DB) GetActivitySummary(ctx context.Context, userExternalID string, scope *disclosure.Scope) (*disclosure.ActivitySummary, error) {
	return d.GetDisclosureActivitySummary(ctx, userExternalID, scope)
}

func (d *DB) GetUserExternalID(ctx context.Context, userID string) (string, error) {
	query := `SELECT external_id FROM users WHERE id = $1`
	var externalID string
	err := d.conn.QueryRowContext(ctx, query, userID).Scan(&externalID)
	if err != nil {
		return "", fmt.Errorf("failed to get user external ID: %w", err)
	}
	return externalID, nil
}
