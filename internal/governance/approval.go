package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// SubmitChange creates a new approval request.
func (e *Engine) SubmitChange(ctx context.Context, orgID, requesterID, changeType string, targetID, targetType *string, payload []byte, approvalsNeeded int) (*rbac.ApprovalRequest, error) {
	req := &rbac.ApprovalRequest{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		RequesterID:        requesterID,
		ChangeType:         changeType,
		TargetResourceID:   targetID,
		TargetResourceType: targetType,
		Payload:            payload,
		Status:             rbac.StatusPending,
		ApprovalsNeeded:    approvalsNeeded,
	}

	if err := e.db.CreateApprovalRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	// Notify asynchronously or synchronously
	if e.notifier != nil {
		_ = e.notifier.NotifyNewRequest(ctx, req) // Ignore errors to not block the flow
	}

	return req, nil
}

// ProcessDecision records an approval or rejection and updates the request status.
func (e *Engine) ProcessDecision(ctx context.Context, orgID, requestID, approverID, decision string, reason *string) (*rbac.ApprovalRequest, error) {
	// First, load the request to perform initial checks outside the transaction.
	// Note: This initial load does not acquire a transactional lock.
	// The lock will be acquired again inside the transaction.
	initialReq, err := e.db.GetApprovalRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to load approval request: %w", err)
	}

	if initialReq.OrgID != orgID {
		return nil, fmt.Errorf("request does not belong to the specified organization")
	}

	if decision != "approve" && decision != "reject" {
		return nil, fmt.Errorf("invalid decision type")
	}

    // The check is moved into the transaction below to prevent race conditions.

	var updatedReq *rbac.ApprovalRequest
	var req *rbac.ApprovalRequest // This 'req' will be used inside the transaction
	err = e.db.WithTx(ctx, func(tx *db.Tx) error {
		var txErr error
		// Acquire a transactional lock on the request
		req, txErr = tx.LockApprovalRequest(ctx, requestID)
		if txErr != nil {
			return fmt.Errorf("failed to lock request: %w", txErr)
		}

		if req.Status != rbac.StatusPending {
			return fmt.Errorf("request is no longer pending (status: %s)", req.Status)
		}

		// Re-evaluate approver eligibility strictly under the database lock to enforce consistency.
		isApprover, errCheck := e.db.IsGovernanceApprover(ctx, orgID, approverID)
		if errCheck != nil {
			return fmt.Errorf("failed to check approver eligibility: %w", errCheck)
		}
		if !isApprover {
			return fmt.Errorf("user is not a designated approver for this organization")
		}

		if req.RequesterID == approverID {
			return fmt.Errorf("requester cannot approve their own request")
		}

		// Insert decision
		dec := &rbac.ApprovalDecision{
			ID:         uuid.New().String(),
			RequestID:  requestID,
			ApproverID: approverID,
			Decision:   decision,
			Reason:     reason,
			DecidedAt:  time.Now(),
		}

		// If a unique constraint fails, they probably already voted
		if err := tx.RecordApprovalDecision(ctx, dec); err != nil {
			return fmt.Errorf("failed to record decision (already voted?): %w", err)
		}

		// If rejected, reject the entire request immediately
		if decision == "reject" {
			now := time.Now()
			req.Status = rbac.StatusRejected
			req.ResolvedAt = &now
			if err := tx.UpdateApprovalRequestStatus(ctx, requestID, req.Status, req.ResolvedAt); err != nil {
				return fmt.Errorf("failed to mark request as rejected: %w", err)
			}
			updatedReq = req
			return nil
		}

		// It's an approval, let's count total approvals
		count, err := tx.CountApprovals(ctx, requestID)
		if err != nil {
			return fmt.Errorf("failed to count approvals: %w", err)
		}

		if count >= req.ApprovalsNeeded {
			// Apply the mutation before finalizing the status
			if e.applier != nil {
				if applyErr := e.applier.ApplyGovernanceMutation(ctx, req); applyErr != nil {
					return fmt.Errorf("failed to apply approved change: %w", applyErr)
				}
			}

			now := time.Now()
			req.Status = rbac.StatusApproved
			req.ResolvedAt = &now
			if err := tx.UpdateApprovalRequestStatus(ctx, requestID, req.Status, req.ResolvedAt); err != nil {
				return fmt.Errorf("failed to mark request as approved: %w", err)
			}
		}

		updatedReq = req
		return nil
	})

	if err != nil {
		return nil, err
	}

	return updatedReq, nil
}
