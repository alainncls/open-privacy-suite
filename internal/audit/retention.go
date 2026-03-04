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
	CleanupExpiredRecords(ctx context.Context) (int64, error)
}

// RetentionManager runs periodic retention cleanup on audit tables.
type RetentionManager struct {
	cfg   RetentionConfig
	store RetentionStore
	stop  chan struct{}
	done  chan struct{}
}

// RetentionCleaner is an alias for RetentionManager for API compatibility.
type RetentionCleaner = RetentionManager

// NewRetentionManager creates a new retention manager. Call Start() to begin cleanup.
func NewRetentionManager(cfg RetentionConfig, store RetentionStore) *RetentionManager {
	return &RetentionManager{
		cfg:   cfg,
		store: store,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
}

// NewRetentionCleaner creates a new retention cleaner. If travelRuleEnabled is false,
// the TravelRecords retention duration is zeroed (skip cleanup). Starts automatically.
func NewRetentionCleaner(cfg RetentionConfig, store RetentionStore, travelRuleEnabled bool) *RetentionCleaner {
	if !travelRuleEnabled {
		cfg.TravelRecords = 0
	}
	mgr := NewRetentionManager(cfg, store)
	mgr.Start()
	return mgr
}

// Start begins the periodic cleanup loop in a goroutine.
func (r *RetentionManager) Start() {
	go r.run()
}

// Stop signals the cleanup loop to stop and waits for it to finish.
func (r *RetentionManager) Stop() {
	close(r.stop)
	<-r.done
}

func (r *RetentionManager) run() {
	defer close(r.done)

	if r.cfg.CleanupInterval <= 0 {
		// Retention disabled.
		return
	}

	// Run cleanup immediately on start, then on interval.
	r.cleanup()

	ticker := time.NewTicker(r.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

func (r *RetentionManager) cleanup() {
	ctx := context.Background()
	now := time.Now()

	type tableCleanup struct {
		name     string
		duration time.Duration
		fn       func(ctx context.Context, olderThan time.Time) (int64, error)
	}

	tables := []tableCleanup{
		{"access_logs", r.cfg.AccessLogs, r.store.CleanupAccessLogs},
		{"compliance_logs", r.cfg.ComplianceLogs, r.store.CleanupComplianceLogs},
		{"rbac_audit_logs", r.cfg.RBACAuditLogs, r.store.CleanupRBACAuditLogs},
		{"travel_records", r.cfg.TravelRecords, r.store.CleanupUsedTravelRecords},
	}

	for _, tc := range tables {
		if tc.duration <= 0 {
			continue
		}

		cutoff := now.Add(-tc.duration)

		// M3 fix: log BEFORE deletion so operators have an auditable trail of retention events.
		log.Printf("Retention: deleting %s older than %s (cutoff: %s)", tc.name, tc.duration, cutoff.Format(time.RFC3339))

		deleted, err := tc.fn(ctx, cutoff)
		if err != nil {
			log.Printf("Retention: error cleaning %s: %v", tc.name, err)
			continue
		}
		if deleted > 0 {
			log.Printf("Retention: deleted %d rows from %s", deleted, tc.name)
		}
	}

	// Always clean up expired records regardless of config.
	expired, err := r.store.CleanupExpiredRecords(ctx)
	if err != nil {
		log.Printf("Retention: error cleaning expired records: %v", err)
	} else if expired > 0 {
		log.Printf("Retention: deleted %d expired records", expired)
	}
}
