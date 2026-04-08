package server

import (
	"sync"
)

// ConcurrencyLimiter caps the number of in-flight requests per user.
// This protects the proxy's own resources (DB connections, CPU) from
// being exhausted by a single user sending many concurrent requests.
// It is NOT rate limiting -- it's a concurrency cap.
type ConcurrencyLimiter struct {
	mu      sync.Mutex
	sems    map[string]chan struct{}
	maxConc int
}

// NewConcurrencyLimiter creates a limiter with the given max concurrent
// requests per user. A value of 0 disables the limiter.
func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		sems:    make(map[string]chan struct{}),
		maxConc: maxConcurrent,
	}
}

// TryAcquire attempts to acquire a slot for the given user.
// Returns true if acquired, false if the user is at the concurrency limit.
func (cl *ConcurrencyLimiter) TryAcquire(userID string) bool {
	if cl.maxConc <= 0 || userID == "" {
		return true // disabled or anonymous
	}

	cl.mu.Lock()
	sem, ok := cl.sems[userID]
	if !ok {
		sem = make(chan struct{}, cl.maxConc)
		cl.sems[userID] = sem
	}
	cl.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release releases a slot for the given user. Must be called after TryAcquire
// returns true, typically via defer.
func (cl *ConcurrencyLimiter) Release(userID string) {
	if cl.maxConc <= 0 || userID == "" {
		return
	}

	cl.mu.Lock()
	sem, ok := cl.sems[userID]
	cl.mu.Unlock()

	if ok {
		select {
		case <-sem:
		default:
			// Should not happen -- Release called without Acquire
		}
	}
}
