package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExplorerVisibilityRateLimiter_SingleCheckAllow(t *testing.T) {
	rl := NewExplorerVisibilityRateLimiter(ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 3,
		BatchMaxRequests:  2,
		WindowSize:        time.Minute,
		CleanupEvery:      time.Hour, // don't interfere
	})
	defer rl.Stop()

	key := "did:test-user:single"

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		assert.True(t, rl.allow(key, 3), "request %d should be allowed", i+1)
	}

	// 4th request should be denied
	assert.False(t, rl.allow(key, 3), "4th request should be denied")
}

func TestExplorerVisibilityRateLimiter_BatchCheckAllow(t *testing.T) {
	rl := NewExplorerVisibilityRateLimiter(ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 10,
		BatchMaxRequests:  2,
		WindowSize:        time.Minute,
		CleanupEvery:      time.Hour,
	})
	defer rl.Stop()

	key := "did:test-user:batch"

	assert.True(t, rl.allow(key, 2))
	assert.True(t, rl.allow(key, 2))
	assert.False(t, rl.allow(key, 2), "3rd batch request should be denied")
}

func TestExplorerVisibilityRateLimiter_DifferentKeysIndependent(t *testing.T) {
	rl := NewExplorerVisibilityRateLimiter(ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 1,
		BatchMaxRequests:  1,
		WindowSize:        time.Minute,
		CleanupEvery:      time.Hour,
	})
	defer rl.Stop()

	assert.True(t, rl.allow("did:user1:single", 1))
	assert.False(t, rl.allow("did:user1:single", 1))
	// Different user should still be allowed
	assert.True(t, rl.allow("did:user2:single", 1))
}

func TestExplorerVisibilityRateLimiter_SingleAndBatchIndependent(t *testing.T) {
	rl := NewExplorerVisibilityRateLimiter(ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 1,
		BatchMaxRequests:  1,
		WindowSize:        time.Minute,
		CleanupEvery:      time.Hour,
	})
	defer rl.Stop()

	// Exhaust single limit
	assert.True(t, rl.allow("did:user1:single", 1))
	assert.False(t, rl.allow("did:user1:single", 1))

	// Batch limit should be independent (different key suffix)
	assert.True(t, rl.allow("did:user1:batch", 1))
	assert.False(t, rl.allow("did:user1:batch", 1))
}

func TestExplorerVisibilityRateLimiter_Cleanup(t *testing.T) {
	rl := NewExplorerVisibilityRateLimiter(ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 1,
		BatchMaxRequests:  1,
		WindowSize:        50 * time.Millisecond,
		CleanupEvery:      time.Hour, // manual cleanup
	})
	defer rl.Stop()

	// Exhaust limit
	assert.True(t, rl.allow("test:single", 1))
	assert.False(t, rl.allow("test:single", 1))

	// Wait for window to expire
	time.Sleep(100 * time.Millisecond)

	// After window expires, should be allowed again
	assert.True(t, rl.allow("test:single", 1))
}

func TestExplorerVisibilityRateLimiter_DefaultConfig(t *testing.T) {
	cfg := DefaultExplorerVisibilityRateLimiterConfig()
	assert.Equal(t, 30, cfg.SingleMaxRequests)
	assert.Equal(t, 10, cfg.BatchMaxRequests)
	assert.Equal(t, time.Minute, cfg.WindowSize)
}

func TestExplorerVisibilityRateLimiter_DevConfig(t *testing.T) {
	cfg := DevExplorerVisibilityRateLimiterConfig()
	assert.Equal(t, 1000, cfg.SingleMaxRequests)
	assert.Equal(t, 1000, cfg.BatchMaxRequests)
}
