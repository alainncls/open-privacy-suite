package governance

import (
	"encoding/json"
	"time"
)

type ApprovalRequestStatus string

const (
	StatusPending  ApprovalRequestStatus = "pending"
	StatusApproved ApprovalRequestStatus = "approved"
	StatusRejected ApprovalRequestStatus = "rejected"
)

type ApprovalRequest struct {
	ID                 string                `json:"id"`
	OrgID              string                `json:"org_id"`
	RequesterID        string                `json:"requester_id"`
	ChangeType         string                `json:"change_type"`
	TargetResourceID   *string               `json:"target_resource_id,omitempty"`
	TargetResourceType *string               `json:"target_resource_type,omitempty"`
	Payload            json.RawMessage       `json:"payload"`
	Status             ApprovalRequestStatus `json:"status"`
	ApprovalsNeeded    int                   `json:"approvals_needed"`
	CreatedAt          time.Time             `json:"created_at"`
	ResolvedAt         *time.Time            `json:"resolved_at,omitempty"`
}

type ApprovalDecision struct {
	ID         string    `json:"id"`
	RequestID  string    `json:"request_id"`
	ApproverID string    `json:"approver_id"`
	Decision   string    `json:"decision"` // "approve" or "reject"
	Reason     *string   `json:"reason,omitempty"`
	DecidedAt  time.Time `json:"decided_at"`
}

type ApprovalNotification struct {
	ID             string     `json:"id"`
	RequestID      string     `json:"request_id"`
	ApproverID     string     `json:"approver_id"`
	Channel        string     `json:"channel"`
	SentAt         time.Time  `json:"sent_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}
