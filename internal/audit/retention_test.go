package audit

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// mockRetentionStore tracks calls to each cleanup method.
type mockRetentionStore struct {
	accessCalls     atomic.Int64
	complianceCalls atomic.Int64
	rbacCalls       atomic.Int64
	travelCalls     atomic.Int64
	expiredCalls    atomic.Int64
	preregCalls     atomic.Int64
	lastPreregTTL   atomic.Int64 // nanoseconds
}

func (m *mockRetentionStore) CleanupAccessLogs(_ context.Context, _ time.Time) (int64, error) {
	m.accessCalls.Add(1)
	return 5, nil
}

func (m *mockRetentionStore) CleanupComplianceLogs(_ context.Context, _ time.Time) (int64, error) {
	m.complianceCalls.Add(1)
	return 3, nil
}

func (m *mockRetentionStore) CleanupRBACAuditLogs(_ context.Context, _ time.Time) (int64, error) {
	m.rbacCalls.Add(1)
	return 2, nil
}

func (m *mockRetentionStore) CleanupUsedTravelRecords(_ context.Context, _ time.Time) (int64, error) {
	m.travelCalls.Add(1)
	return 1, nil
}

func (m *mockRetentionStore) CleanupExpiredRecords(_ context.Context) (int64, error) {
	m.expiredCalls.Add(1)
	return 0, nil
}

func (m *mockRetentionStore) DeleteOrphanedPreregisteredAddresses(_ context.Context, olderThan time.Duration) (int64, error) {
	m.preregCalls.Add(1)
	m.lastPreregTTL.Store(int64(olderThan))
	return 0, nil
}

func TestRetention_DisabledWithZeroInterval(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 0, // disabled
	}, store)

	mgr.Start()
	// Give it a moment to start (it should exit immediately).
	time.Sleep(50 * time.Millisecond)
	mgr.Stop()

	if store.accessCalls.Load() != 0 {
		t.Fatal("expected no cleanup calls when interval is 0")
	}
}

func TestRetention_RunsOnStartAndInterval(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 50 * time.Millisecond,
	}, store)

	mgr.Start()
	// Wait for initial run + at least one tick.
	time.Sleep(120 * time.Millisecond)
	mgr.Stop()

	calls := store.accessCalls.Load()
	if calls < 2 {
		t.Fatalf("expected at least 2 cleanup calls (initial + tick), got %d", calls)
	}
}

func TestRetention_ZeroDurationSkipsTable(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		ComplianceLogs:  0, // skip
		RBACAuditLogs:   0, // skip
		TravelRecords:   0, // skip
		CleanupInterval: 50 * time.Millisecond,
	}, store)

	mgr.Start()
	time.Sleep(80 * time.Millisecond)
	mgr.Stop()

	if store.accessCalls.Load() == 0 {
		t.Fatal("expected access_logs cleanup to run")
	}
	if store.complianceCalls.Load() != 0 {
		t.Fatal("expected compliance_logs cleanup to be skipped (zero duration)")
	}
	if store.rbacCalls.Load() != 0 {
		t.Fatal("expected rbac_audit_logs cleanup to be skipped (zero duration)")
	}
	if store.travelCalls.Load() != 0 {
		t.Fatal("expected travel_records cleanup to be skipped (zero duration)")
	}
	// Expired records always run.
	if store.expiredCalls.Load() == 0 {
		t.Fatal("expected expired records cleanup to always run")
	}
}

func TestRetention_PreregistrationSweepRunsOnInterval(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:                     24 * time.Hour,
		CleanupInterval:                1 * time.Hour, // long, unrelated
		PreregistrationTTL:             30 * time.Minute,
		PreregistrationCleanupInterval: 50 * time.Millisecond,
	}, store)

	mgr.Start()
	time.Sleep(150 * time.Millisecond)
	mgr.Stop()

	calls := store.preregCalls.Load()
	if calls < 2 {
		t.Fatalf("expected at least 2 pre-reg sweep calls (initial + tick), got %d", calls)
	}
	if got := time.Duration(store.lastPreregTTL.Load()); got != 30*time.Minute {
		t.Fatalf("expected pre-reg TTL 30m, got %s", got)
	}
}

func TestRetention_PreregistrationDefaults(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 1 * time.Hour,
		// Leave preregistration fields at zero; defaults should kick in.
	}, store)

	if mgr.cfg.PreregistrationTTL != defaultPreregistrationTTL {
		t.Fatalf("expected default pre-reg TTL %s, got %s", defaultPreregistrationTTL, mgr.cfg.PreregistrationTTL)
	}
	if mgr.cfg.PreregistrationCleanupInterval != defaultPreregistrationCleanup {
		t.Fatalf("expected default pre-reg interval %s, got %s", defaultPreregistrationCleanup, mgr.cfg.PreregistrationCleanupInterval)
	}
}

func TestRetention_StopChannelWorks(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 1 * time.Hour, // long interval
	}, store)

	mgr.Start()
	// Stop immediately - should not hang.
	done := make(chan struct{})
	go func() {
		mgr.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return in time")
	}
}
