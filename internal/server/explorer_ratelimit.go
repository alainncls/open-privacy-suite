package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ExplorerVisibilityRateLimiter provides per-viewer rate limiting for the
// explorer visibility check endpoints (check-address and check-addresses).
// The key is either the viewer's DID (from JWT) or the client IP for anonymous
// requests.
type ExplorerVisibilityRateLimiter struct {
	mu           sync.Mutex
	requests     map[string][]time.Time // key -> request timestamps
	windowSize   time.Duration
	cleanupEvery time.Duration
	stopCleanup  chan struct{}
	wg           sync.WaitGroup
}

// ExplorerVisibilityRateLimiterConfig holds limits for the two visibility endpoints.
type ExplorerVisibilityRateLimiterConfig struct {
	SingleMaxRequests int           // max requests per window for single check (default: 30)
	BatchMaxRequests  int           // max requests per window for batch check (default: 10)
	WindowSize        time.Duration // sliding window (default: 1 minute)
	CleanupEvery      time.Duration // cleanup interval (default: 5 minutes)
}

// DefaultExplorerVisibilityRateLimiterConfig returns production defaults.
func DefaultExplorerVisibilityRateLimiterConfig() ExplorerVisibilityRateLimiterConfig {
	return ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 30,
		BatchMaxRequests:  10,
		WindowSize:        time.Minute,
		CleanupEvery:      5 * time.Minute,
	}
}

// DevExplorerVisibilityRateLimiterConfig returns relaxed limits for development/testing.
func DevExplorerVisibilityRateLimiterConfig() ExplorerVisibilityRateLimiterConfig {
	return ExplorerVisibilityRateLimiterConfig{
		SingleMaxRequests: 1000,
		BatchMaxRequests:  1000,
		WindowSize:        time.Minute,
		CleanupEvery:      5 * time.Minute,
	}
}

// NewExplorerVisibilityRateLimiter creates a new rate limiter for visibility endpoints.
func NewExplorerVisibilityRateLimiter(cfg ExplorerVisibilityRateLimiterConfig) *ExplorerVisibilityRateLimiter {
	if cfg.SingleMaxRequests <= 0 {
		cfg.SingleMaxRequests = 30
	}
	if cfg.BatchMaxRequests <= 0 {
		cfg.BatchMaxRequests = 10
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = time.Minute
	}
	if cfg.CleanupEvery <= 0 {
		cfg.CleanupEvery = 5 * time.Minute
	}

	rl := &ExplorerVisibilityRateLimiter{
		requests:     make(map[string][]time.Time),
		windowSize:   cfg.WindowSize,
		cleanupEvery: cfg.CleanupEvery,
		stopCleanup:  make(chan struct{}),
	}

	rl.wg.Add(1)
	go rl.cleanup()

	return rl
}

// viewerKey returns the rate-limit key for the current request: DID if
// authenticated, otherwise client IP.
func viewerKey(c *gin.Context) string {
	if did, exists := c.Get("subject"); exists {
		if s, ok := did.(string); ok && s != "" {
			return "did:" + s
		}
	}
	return "ip:" + c.ClientIP()
}

// allow checks whether the viewer identified by key is under the given limit
// within the sliding window, and records the request if allowed.
func (rl *ExplorerVisibilityRateLimiter) allow(key string, maxRequests int) bool {
	now := time.Now()
	cutoff := now.Add(-rl.windowSize)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	timestamps := rl.requests[key]

	// Filter out old timestamps
	valid := make([]time.Time, 0, len(timestamps))
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	if len(valid) >= maxRequests {
		rl.requests[key] = valid
		return false
	}

	valid = append(valid, now)
	rl.requests[key] = valid
	return true
}

// SingleCheckMiddleware returns a Gin middleware that rate-limits the single
// address visibility check endpoint.
func (rl *ExplorerVisibilityRateLimiter) SingleCheckMiddleware(maxRequests int) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := viewerKey(c)
		if !rl.allow(key+":single", maxRequests) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "visibility check rate limit exceeded, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// BatchCheckMiddleware returns a Gin middleware that rate-limits the batch
// address visibility check endpoint.
func (rl *ExplorerVisibilityRateLimiter) BatchCheckMiddleware(maxRequests int) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := viewerKey(c)
		if !rl.allow(key+":batch", maxRequests) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "batch visibility check rate limit exceeded, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// cleanup periodically removes old entries.
func (rl *ExplorerVisibilityRateLimiter) cleanup() {
	defer rl.wg.Done()
	ticker := time.NewTicker(rl.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.doCleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

func (rl *ExplorerVisibilityRateLimiter) doCleanup() {
	cutoff := time.Now().Add(-rl.windowSize * 2)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	for key, timestamps := range rl.requests {
		valid := make([]time.Time, 0, len(timestamps))
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, key)
		} else {
			rl.requests[key] = valid
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *ExplorerVisibilityRateLimiter) Stop() {
	close(rl.stopCleanup)
	rl.wg.Wait()
}
