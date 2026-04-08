package server

import (
	"sync"
	"time"
)

// CircuitBreaker tracks upstream 429 responses per API key.
// When tripped, subsequent requests are rejected immediately for the
// cooldown period (1 second, matching the RPC proxy's rate limit window).
type CircuitBreaker struct {
	mu       sync.RWMutex
	tripped  map[string]time.Time // apiKey -> last 429 timestamp
	cooldown time.Duration
}

// NewCircuitBreaker creates a circuit breaker with a 1-second cooldown.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		tripped:  make(map[string]time.Time),
		cooldown: time.Second,
	}
}

// IsOpen returns true if the circuit is open (should reject requests).
func (cb *CircuitBreaker) IsOpen(apiKey string) bool {
	if apiKey == "" {
		return false // no API key = no circuit to trip
	}
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	t, ok := cb.tripped[apiKey]
	if !ok {
		return false
	}
	return time.Since(t) < cb.cooldown
}

// Trip records a 429 for the given API key.
func (cb *CircuitBreaker) Trip(apiKey string) {
	if apiKey == "" {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripped[apiKey] = time.Now()
}

// Reset clears the trip state for an API key (on successful response).
func (cb *CircuitBreaker) Reset(apiKey string) {
	if apiKey == "" {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.tripped, apiKey)
}
