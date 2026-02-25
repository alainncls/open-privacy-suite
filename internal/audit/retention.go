package audit

import (
	"context"
	"log"
	"time"
)

// RetentionConfig holds per-table retention durations and the cleanup interval.
// A zero duration means "keep forever" (skip cleanup for that table).
type RetentionConfig struct {
	AccessLogs      time.Duration
	ComplianceLogs  time.Duration
	RBACAuditLogs   time.Duration
	TravelRecords   time.Duration
	CleanupInterval time.Duration
}

// RetentionStore defines the database operations needed for retention cleanup.
type RetentionStore interface {
	CleanupAccessLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupComplianceLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupRBACAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupUsedTravelRecords(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupExpiredRecords(ctx context.Context) (int64, error) // unused expired travel records
}

// RetentionCleaner runs periodic cleanup of old audit records.
type RetentionCleaner struct {
	config          RetentionConfig
	store           RetentionStore
	travelRuleActive bool
	stopCh          chan struct{}
	doneCh          chan struct{}
}

// NewRetentionCleaner creates and starts a background retention cleaner.
func NewRetentionCleaner(cfg RetentionConfig, store RetentionStore, travelRuleActive bool) *RetentionCleaner {
	rc := &RetentionCleaner{
		config:           cfg,
		store:            store,
		travelRuleActive: travelRuleActive,
		stopCh:           make(chan struct{}),
		doneCh:           make(chan struct{}),
	}
	go rc.run()
	return rc
}

// Stop gracefully stops the retention cleaner and waits for the goroutine to exit.
func (rc *RetentionCleaner) Stop() {
	close(rc.stopCh)
	<-rc.doneCh
}

func (rc *RetentionCleaner) run() {
	defer close(rc.doneCh)

	// Run cleanup immediately on startup
	rc.cleanup()

	ticker := time.NewTicker(rc.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rc.cleanup()
		case <-rc.stopCh:
			return
		}
	}
}

func (rc *RetentionCleaner) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if rc.config.AccessLogs > 0 {
		cutoff := time.Now().Add(-rc.config.AccessLogs)
		if count, err := rc.store.CleanupAccessLogs(ctx, cutoff); err != nil {
			log.Printf("Retention cleanup error (access_logs): %v", err)
		} else if count > 0 {
			log.Printf("Retention cleanup: deleted %d access_logs older than %s", count, rc.config.AccessLogs)
		}
	}

	if rc.config.ComplianceLogs > 0 {
		cutoff := time.Now().Add(-rc.config.ComplianceLogs)
		if count, err := rc.store.CleanupComplianceLogs(ctx, cutoff); err != nil {
			log.Printf("Retention cleanup error (compliance_logs): %v", err)
		} else if count > 0 {
			log.Printf("Retention cleanup: deleted %d compliance_logs older than %s", count, rc.config.ComplianceLogs)
		}
	}

	if rc.config.RBACAuditLogs > 0 {
		cutoff := time.Now().Add(-rc.config.RBACAuditLogs)
		if count, err := rc.store.CleanupRBACAuditLogs(ctx, cutoff); err != nil {
			log.Printf("Retention cleanup error (rbac_audit_log): %v", err)
		} else if count > 0 {
			log.Printf("Retention cleanup: deleted %d rbac_audit_log entries older than %s", count, rc.config.RBACAuditLogs)
		}
	}

	if rc.config.TravelRecords > 0 {
		cutoff := time.Now().Add(-rc.config.TravelRecords)
		if count, err := rc.store.CleanupUsedTravelRecords(ctx, cutoff); err != nil {
			log.Printf("Retention cleanup error (travel_rule_records): %v", err)
		} else if count > 0 {
			log.Printf("Retention cleanup: deleted %d used travel_rule_records older than %s", count, rc.config.TravelRecords)
		}
	}

	// Also clean up expired unused travel rule records when travel rule is active
	if rc.travelRuleActive {
		if count, err := rc.store.CleanupExpiredRecords(ctx); err != nil {
			log.Printf("Retention cleanup error (expired travel records): %v", err)
		} else if count > 0 {
			log.Printf("Retention cleanup: deleted %d expired unused travel_rule_records", count)
		}
	}
}
