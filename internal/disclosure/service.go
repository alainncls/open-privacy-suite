package disclosure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRequestNotFound     = errors.New("disclosure request not found")
	ErrRequestNotPending   = errors.New("disclosure request is not pending")
	ErrRequestExpired      = errors.New("disclosure request has expired")
	ErrGrantNotFound       = errors.New("disclosure grant not found")
	ErrGrantNotActive      = errors.New("disclosure grant is not active")
	ErrInvalidToken        = errors.New("invalid disclosure token")
	ErrUnauthorized        = errors.New("unauthorized to perform this action")
	ErrScopeOutOfBounds    = errors.New("requested scope exceeds granted scope")
)

// DefaultService implements the Service interface.
type DefaultService struct {
	store Store
}

// NewService creates a new disclosure service.
func NewService(store Store) *DefaultService {
	return &DefaultService{store: store}
}

// CreateRequest creates a new disclosure request.
func (s *DefaultService) CreateRequest(ctx context.Context, requesterUserID, requesterDID, targetUserID, orgID string, scope Scope, reason, legalBasis string, expiresIn *time.Duration) (*Request, error) {
	req := &Request{
		ID:              uuid.New().String(),
		RequesterDID:    requesterDID,
		TargetUserID:    targetUserID,
		OrgID:           orgID,
		Scope:           scope,
		Reason:          reason,
		LegalBasis:      legalBasis,
		Status:          StatusPending,
		RequestedAt:     time.Now(),
	}

	if requesterUserID != "" {
		req.RequesterUserID = &requesterUserID
	}

	if expiresIn != nil {
		expiresAt := time.Now().Add(*expiresIn)
		req.ExpiresAt = &expiresAt
	}

	if err := s.store.CreateRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return req, nil
}

// ApproveRequest approves a disclosure request and creates a grant.
// Access is controlled via requester_did - no token needed for DID-based auth.
func (s *DefaultService) ApproveRequest(ctx context.Context, requestID, decidedByUserID string, narrowedScope *Scope, grantDuration time.Duration, reason string) (*Grant, error) {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrRequestNotFound
	}

	if req.Status != StatusPending {
		return nil, ErrRequestNotPending
	}
	if req.IsExpired() {
		return nil, ErrRequestExpired
	}

	// Determine granted scope (may be narrower than requested)
	grantedScope := req.Scope
	if narrowedScope != nil {
		grantedScope = *narrowedScope
	}

	// Create grant - use a placeholder hash since we're using DID-based auth now
	grant := &Grant{
		ID:             uuid.New().String(),
		RequestID:      requestID,
		GrantTokenHash: fmt.Sprintf("did-auth-%s", uuid.New().String()), // Placeholder for DID-based auth
		Scope:          grantedScope,
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(grantDuration),
	}

	if err := s.store.CreateGrant(ctx, grant); err != nil {
		return nil, fmt.Errorf("failed to create grant: %w", err)
	}

	// Update request status
	if err := s.store.UpdateRequestStatus(ctx, requestID, StatusApproved, &decidedByUserID, reason); err != nil {
		return nil, fmt.Errorf("failed to update request status: %w", err)
	}

	return grant, nil
}

// RejectRequest rejects a disclosure request.
func (s *DefaultService) RejectRequest(ctx context.Context, requestID, decidedByUserID, reason string) error {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrRequestNotFound
	}

	if req.Status != StatusPending {
		return ErrRequestNotPending
	}

	return s.store.UpdateRequestStatus(ctx, requestID, StatusRejected, &decidedByUserID, reason)
}

// RevokeRequest revokes an approved request (and its grant).
func (s *DefaultService) RevokeRequest(ctx context.Context, requestID, revokedByUserID, reason string) error {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrRequestNotFound
	}

	// Revoke any active grants
	grant, err := s.store.GetActiveGrantForRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if grant != nil {
		if err := s.store.RevokeGrant(ctx, grant.ID, reason); err != nil {
			return fmt.Errorf("failed to revoke grant: %w", err)
		}
	}

	return s.store.UpdateRequestStatus(ctx, requestID, StatusRevoked, &revokedByUserID, reason)
}

// ValidateGrantToken validates a disclosure token and returns the grant with request.
func (s *DefaultService) ValidateGrantToken(ctx context.Context, token string) (*GrantWithRequest, error) {
	tokenHash := hashToken(token)

	grant, err := s.store.GetGrantByToken(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, ErrInvalidToken
	}

	if !grant.IsActive() {
		return nil, ErrGrantNotActive
	}

	req, err := s.store.GetRequest(ctx, grant.RequestID)
	if err != nil {
		return nil, err
	}

	return &GrantWithRequest{Grant: grant, Request: req}, nil
}

// RevokeGrant revokes a disclosure grant.
func (s *DefaultService) RevokeGrant(ctx context.Context, grantID, reason string) error {
	grant, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if grant == nil {
		return ErrGrantNotFound
	}

	return s.store.RevokeGrant(ctx, grantID, reason)
}

// GetActivityLogs retrieves activity logs within the granted scope.
func (s *DefaultService) GetActivityLogs(ctx context.Context, grantID, viewerUserID, viewerIP string, limit, offset int) ([]*ActivityLogEntry, error) {
	grantWithReq, err := s.store.GetGrantWithRequest(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if grantWithReq == nil || grantWithReq.Grant == nil {
		return nil, ErrGrantNotFound
	}

	if !grantWithReq.Grant.IsActive() {
		return nil, ErrGrantNotActive
	}

	// Get target user's external ID from internal ID
	req := grantWithReq.Request
	targetUserExternalID, err := s.store.GetUserExternalID(ctx, req.TargetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target user external ID: %w", err)
	}

	// Query activity logs using the external ID
	logs, err := s.store.GetActivityLogs(ctx, targetUserExternalID, &grantWithReq.Grant.Scope, limit, offset)
	if err != nil {
		return nil, err
	}

	// Log this access event
	event := &Event{
		GrantID:      grantID,
		Action:       ActionViewLogs,
		ResourceType: ResourceAccessLogs,
		ViewerIP:     viewerIP,
		AccessedAt:   time.Now(),
		DataSummary: &DataSummary{
			RecordCount: len(logs),
		},
	}
	if viewerUserID != "" {
		event.ViewerUserID = &viewerUserID
	}

	_ = s.store.CreateEvent(ctx, event) // Best effort logging

	return logs, nil
}

// GetActivitySummary retrieves an activity summary within the granted scope.
func (s *DefaultService) GetActivitySummary(ctx context.Context, grantID, viewerUserID, viewerIP string) (*ActivitySummary, error) {
	grantWithReq, err := s.store.GetGrantWithRequest(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if grantWithReq == nil || grantWithReq.Grant == nil {
		return nil, ErrGrantNotFound
	}

	if !grantWithReq.Grant.IsActive() {
		return nil, ErrGrantNotActive
	}

	req := grantWithReq.Request
	targetUserExternalID, err := s.store.GetUserExternalID(ctx, req.TargetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target user external ID: %w", err)
	}

	summary, err := s.store.GetActivitySummary(ctx, targetUserExternalID, &grantWithReq.Grant.Scope)
	if err != nil {
		return nil, err
	}

	// Log this access event
	event := &Event{
		GrantID:      grantID,
		Action:       ActionViewSummary,
		ResourceType: ResourceSummary,
		ViewerIP:     viewerIP,
		AccessedAt:   time.Now(),
		DataSummary: &DataSummary{
			RecordCount: summary.TotalRequests,
			DateRange:   summary.DateRange,
		},
	}
	if viewerUserID != "" {
		event.ViewerUserID = &viewerUserID
	}

	_ = s.store.CreateEvent(ctx, event)

	return summary, nil
}

// GenerateComplianceReport generates a compliance report.
func (s *DefaultService) GenerateComplianceReport(ctx context.Context, grantID, viewerUserID, viewerIP string, reportType ReportType) (*Report, error) {
	grantWithReq, err := s.store.GetGrantWithRequest(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if grantWithReq == nil || grantWithReq.Grant == nil {
		return nil, ErrGrantNotFound
	}

	if !grantWithReq.Grant.IsActive() {
		return nil, ErrGrantNotActive
	}

	// Check for cached report
	existing, err := s.store.GetReportByGrantAndType(ctx, grantID, reportType)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	// Generate new report based on type
	req := grantWithReq.Request
	targetUserExternalID, err := s.store.GetUserExternalID(ctx, req.TargetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target user external ID: %w", err)
	}

	var reportData map[string]any

	switch reportType {
	case ReportActivitySummary:
		summary, err := s.store.GetActivitySummary(ctx, targetUserExternalID, &grantWithReq.Grant.Scope)
		if err != nil {
			return nil, err
		}
		reportData = map[string]any{
			"type":               "activity_summary",
			"target_user_id":     req.TargetUserID,
			"total_requests":     summary.TotalRequests,
			"successful_count":   summary.SuccessfulCount,
			"failed_count":       summary.FailedCount,
			"unique_methods":     summary.UniqueMethodCount,
			"method_breakdown":   summary.MethodBreakdown,
			"date_range":         summary.DateRange,
			"generated_at":       time.Now(),
		}

	case ReportSanctionsCheck:
		// For now, return a clean sanctions check
		// In production, this would integrate with actual sanctions lists
		reportData = map[string]any{
			"type":                "sanctions_check",
			"target_user_id":      req.TargetUserID,
			"checked_at":          time.Now(),
			"is_clear":            true,
			"sanctioned_addresses": []string{},
			"scope":               grantWithReq.Grant.Scope,
		}

	case ReportCompliance:
		summary, err := s.store.GetActivitySummary(ctx, targetUserExternalID, &grantWithReq.Grant.Scope)
		if err != nil {
			return nil, err
		}
		reportData = map[string]any{
			"type":             "compliance_report",
			"target_user_id":   req.TargetUserID,
			"generated_at":     time.Now(),
			"scope":            grantWithReq.Grant.Scope,
			"activity_summary": summary,
			"sanctions_clear":  true,
			"kyc_verified":     false, // Would need to fetch from user
		}

	default:
		return nil, fmt.Errorf("unknown report type: %s", reportType)
	}

	report := &Report{
		ID:          uuid.New().String(),
		GrantID:     grantID,
		ReportType:  reportType,
		ReportData:  reportData,
		GeneratedAt: time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour), // Reports valid for 24 hours
	}

	if err := s.store.CreateReport(ctx, report); err != nil {
		return nil, fmt.Errorf("failed to save report: %w", err)
	}

	// Log this access event
	event := &Event{
		GrantID:      grantID,
		Action:       ActionExportReport,
		ResourceType: ResourceReport,
		ViewerIP:     viewerIP,
		AccessedAt:   time.Now(),
		DataSummary: &DataSummary{
			Methods: []string{string(reportType)},
		},
	}
	if viewerUserID != "" {
		event.ViewerUserID = &viewerUserID
	}

	_ = s.store.CreateEvent(ctx, event)

	return report, nil
}

// GetMyPendingRequests returns pending disclosure requests for a user.
func (s *DefaultService) GetMyPendingRequests(ctx context.Context, userID string) ([]*RequestWithDetails, error) {
	return s.store.ListPendingRequestsForUser(ctx, userID)
}

// GetMyActiveGrants returns active disclosure grants for a user's data.
func (s *DefaultService) GetMyActiveGrants(ctx context.Context, userID string) ([]*GrantWithRequest, error) {
	return s.store.ListActiveGrantsForTarget(ctx, userID)
}

// ListAllRequests lists all disclosure requests for an organization.
func (s *DefaultService) ListAllRequests(ctx context.Context, orgID string, status *RequestStatus) ([]*RequestWithDetails, error) {
	requests, err := s.store.ListRequestsByOrg(ctx, orgID, status)
	if err != nil {
		return nil, err
	}

	// Convert to RequestWithDetails (without full details for efficiency)
	var results []*RequestWithDetails
	for _, req := range requests {
		results = append(results, &RequestWithDetails{Request: req})
	}
	return results, nil
}

// ExpireOldRequests expires pending requests that have passed their expiration.
func (s *DefaultService) ExpireOldRequests(ctx context.Context) (int64, error) {
	return s.store.ExpirePendingRequests(ctx)
}

// CleanupExpiredReports removes expired report records.
func (s *DefaultService) CleanupExpiredReports(ctx context.Context) (int64, error) {
	return s.store.DeleteExpiredReports(ctx)
}

// ListRequestsWithFilter returns filtered disclosure requests.
func (s *DefaultService) ListRequestsWithFilter(ctx context.Context, filter *DisclosureFilter) (*DisclosureListResult, error) {
	if filter == nil {
		filter = NewDefaultFilter()
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	return s.store.ListRequestsWithFilter(ctx, filter)
}

// ListGrantsWithFilter returns filtered disclosure grants.
func (s *DefaultService) ListGrantsWithFilter(ctx context.Context, filter *DisclosureFilter) (*GrantListResult, error) {
	if filter == nil {
		filter = NewDefaultFilter()
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	return s.store.ListGrantsWithFilter(ctx, filter)
}

// DeletePendingRequest deletes a pending disclosure request (admin action).
func (s *DefaultService) DeletePendingRequest(ctx context.Context, requestID string) error {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrRequestNotFound
	}

	if req.Status != StatusPending {
		return ErrRequestNotPending
	}

	return s.store.DeleteRequest(ctx, requestID)
}

// GetAllMyRequests returns all disclosure requests for a user (not just pending).
func (s *DefaultService) GetAllMyRequests(ctx context.Context, userID string) ([]*RequestWithDetails, error) {
	return s.store.ListAllRequestsForUser(ctx, userID)
}

// GetAllMyGrants returns all disclosure grants for a user's data (not just active).
func (s *DefaultService) GetAllMyGrants(ctx context.Context, userID string) ([]*GrantWithRequest, error) {
	return s.store.ListAllGrantsForTarget(ctx, userID)
}

// hashToken creates a SHA256 hash of a token.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
