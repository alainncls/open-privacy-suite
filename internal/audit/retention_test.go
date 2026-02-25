package audit

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockRetentionStore struct {
	accessCount     atomic.Int64
	complianceCount atomic.Int64
	rbacCount       atomic.Int64
	travelCount     atomic.Int64
	expiredCount    atomic.Int64
}

func (m *mockRetentionStore) CleanupAccessLogs(_ context.Context, _ time.Time) (int64, error) {
	m.accessCount.Add(1)
	return 5, nil
}

func (m *mockRetentionStore) CleanupComplianceLogs(_ context.Context, _ time.Time) (int64, error) {
	m.complianceCount.Add(1)
	return 3, nil
}

func (m *mockRetentionStore) CleanupRBACAuditLogs(_ context.Context, _ time.Time) (int64, error) {
	m.rbacCount.Add(1)
	return 2, nil
}

func (m *mockRetentionStore) CleanupUsedTravelRecords(_ context.Context, _ time.Time) (int64, error) {
	m.travelCount.Add(1)
	return 1, nil
}

func (m *mockRetentionStore) CleanupExpiredRecords(_ context.Context) (int64, error) {
	m.expiredCount.Add(1)
	return 4, nil
}

func TestRetentionCleaner_RunsOnStartup(t *testing.T) {
	store := &mockRetentionStore{}
	cfg := RetentionConfig{
		AccessLogs:      90 * 24 * time.Hour,
		ComplianceLogs:  7 * 365 * 24 * time.Hour,
		RBACAuditLogs:   365 * 24 * time.Hour,
		TravelRecords:   7 * 365 * 24 * time.Hour,
		CleanupInterval: 1 * time.Hour, // won't fire in test
	}

	cleaner := NewRetentionCleaner(cfg, store, true)
	// Give startup cleanup time to run
	time.Sleep(100 * time.Millisecond)
	cleaner.Stop()

	assert.GreaterOrEqual(t, store.accessCount.Load(), int64(1))
	assert.GreaterOrEqual(t, store.complianceCount.Load(), int64(1))
	assert.GreaterOrEqual(t, store.rbacCount.Load(), int64(1))
	assert.GreaterOrEqual(t, store.travelCount.Load(), int64(1))
	assert.GreaterOrEqual(t, store.expiredCount.Load(), int64(1))
}

func TestRetentionCleaner_SkipsZeroDuration(t *testing.T) {
	store := &mockRetentionStore{}
	cfg := RetentionConfig{
		AccessLogs:      0, // keep forever
		ComplianceLogs:  0, // keep forever
		RBACAuditLogs:   0, // keep forever
		TravelRecords:   0, // keep forever
		CleanupInterval: 1 * time.Hour,
	}

	cleaner := NewRetentionCleaner(cfg, store, false)
	time.Sleep(100 * time.Millisecond)
	cleaner.Stop()

	assert.Equal(t, int64(0), store.accessCount.Load())
	assert.Equal(t, int64(0), store.complianceCount.Load())
	assert.Equal(t, int64(0), store.rbacCount.Load())
	assert.Equal(t, int64(0), store.travelCount.Load())
	assert.Equal(t, int64(0), store.expiredCount.Load())
}

func TestRetentionCleaner_SkipsExpiredWhenTravelRuleInactive(t *testing.T) {
	store := &mockRetentionStore{}
	cfg := RetentionConfig{
		AccessLogs:      90 * 24 * time.Hour,
		CleanupInterval: 1 * time.Hour,
	}

	cleaner := NewRetentionCleaner(cfg, store, false) // travel rule inactive
	time.Sleep(100 * time.Millisecond)
	cleaner.Stop()

	assert.GreaterOrEqual(t, store.accessCount.Load(), int64(1))
	assert.Equal(t, int64(0), store.expiredCount.Load())
}

func TestRetentionCleaner_StopsGracefully(t *testing.T) {
	store := &mockRetentionStore{}
	cfg := RetentionConfig{
		CleanupInterval: 50 * time.Millisecond,
	}

	cleaner := NewRetentionCleaner(cfg, store, false)
	time.Sleep(200 * time.Millisecond)

	// Stop should return without hanging
	done := make(chan struct{})
	go func() {
		cleaner.Stop()
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2 seconds")
	}
}
