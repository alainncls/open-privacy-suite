package audit

import (
	"context"
	"log/slog"
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

	// PreregistrationTTL is the age above which orphaned preregistered_addresses
	// rows (pre-reg rows with no matching contracts row) are deleted. A zero
	// value means "use the default" (see defaultPreregistrationTTL).
	PreregistrationTTL time.Duration
	// PreregistrationCleanupInterval controls how often the orphan sweep runs.
	// A zero value means "use the default" (see defaultPreregistrationCleanup).
	PreregistrationCleanupInterval time.Duration
}

const (
	// defaultPreregistrationTTL is the default age threshold for considering a
	// preregistered_addresses row orphaned. Normal deployments finalize in seconds;
	// 1h is conservative.
	defaultPreregistrationTTL = 1 * time.Hour
	// defaultPreregistrationCleanup is the default interval between orphan sweeps.
	defaultPreregistrationCleanup = 5 * time.Minute
)

// RetentionStore defines the database operations needed for retention cleanup.
type RetentionStore interface {
	CleanupAccessLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupComplianceLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupRBACAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupUsedTravelRecords(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupExpiredRecords(ctx context.Context) (int64, error)

	// DeleteOrphanedPreregisteredAddresses deletes preregistered_addresses rows older
	// than olderThan that have no matching contracts row (abandoned / crash-leftover).
	DeleteOrphanedPreregisteredAddresses(ctx context.Context, olderThan time.Duration) (int64, error)
}

// RetentionManager runs periodic retention cleanup on audit tables.
type RetentionManager struct {
	cfg       RetentionConfig
	store     RetentionStore
	stop      chan struct{}
	done      chan struct{}
	preregDon chan struct{}
}

// RetentionCleaner is an alias for RetentionManager for API compatibility.
type RetentionCleaner = RetentionManager

// NewRetentionManager creates a new retention manager. Call Start() to begin cleanup.
func NewRetentionManager(cfg RetentionConfig, store RetentionStore) *RetentionManager {
	if cfg.PreregistrationTTL <= 0 {
		cfg.PreregistrationTTL = defaultPreregistrationTTL
	}
	if cfg.PreregistrationCleanupInterval <= 0 {
		cfg.PreregistrationCleanupInterval = defaultPreregistrationCleanup
	}
	return &RetentionManager{
		cfg:       cfg,
		store:     store,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		preregDon: make(chan struct{}),
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
	go r.runPreregistrationCleanup()
}

// Stop signals the cleanup loop to stop and waits for it to finish.
func (r *RetentionManager) Stop() {
	close(r.stop)
	<-r.done
	<-r.preregDon
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
		slog.Info("retention: deleting old records", "table", tc.name, "retention", tc.duration, "cutoff", cutoff.Format(time.RFC3339))

		deleted, err := tc.fn(ctx, cutoff)
		if err != nil {
			slog.Error("retention: error cleaning table", "table", tc.name, "error", err)
			continue
		}
		if deleted > 0 {
			slog.Info("retention: deleted rows", "table", tc.name, "count", deleted)
		}
	}

	// Always clean up expired records regardless of config.
	expired, err := r.store.CleanupExpiredRecords(ctx)
	if err != nil {
		slog.Error("retention: error cleaning expired records", "error", err)
	} else if expired > 0 {
		slog.Info("retention: deleted expired records", "count", expired)
	}
}

// runPreregistrationCleanup periodically deletes orphaned preregistered_addresses
// rows. It runs on its own ticker independent of the audit retention cadence
// because pre-registration leaks (from proxy crashes between pre-reg and the
// post-mine / revert cleanup paths) are a security-relevant footprint that
// should be swept aggressively.
func (r *RetentionManager) runPreregistrationCleanup() {
	defer close(r.preregDon)

	interval := r.cfg.PreregistrationCleanupInterval
	ttl := r.cfg.PreregistrationTTL
	if interval <= 0 || ttl <= 0 {
		return
	}

	r.sweepOrphanedPreregistrations(ttl)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.sweepOrphanedPreregistrations(ttl)
		}
	}
}

func (r *RetentionManager) sweepOrphanedPreregistrations(ttl time.Duration) {
	ctx := context.Background()
	deleted, err := r.store.DeleteOrphanedPreregisteredAddresses(ctx, ttl)
	if err != nil {
		slog.Error("retention: error cleaning orphaned preregistered addresses", "error", err)
		return
	}
	if deleted > 0 {
		slog.Info("retention: deleted orphaned preregistered addresses", "count", deleted, "ttl", ttl)
	}
}
