package rbac

import (
	"sync"
	"time"

	"privacy-proxy/internal/evm/bytecode"
)

// PendingDeployment represents a deployment waiting to be confirmed.
type PendingDeployment struct {
	TxHash      string
	OrgID       string
	IsProxy     bool
	ProxyType   string
	ProxyInfo   *bytecode.ProxyInfo
	SubmittedAt time.Time
	// Fields for plain CREATE pre-registration cleanup/finalization.
	IsPlainCreate     bool   // true when this is a plain CREATE (not CREATE3/proxy)
	PreRegisteredAddr string // address inserted into preregistered_addresses; empty if not pre-registered
	DeployerUserID    string // internal user UUID, for the contract record DeployedByUserID
}

// PendingDeploymentTracker tracks proxy deployments waiting for confirmation.
// It is thread-safe and supports automatic cleanup of expired entries.
type PendingDeploymentTracker struct {
	mu      sync.RWMutex
	pending map[string]*PendingDeployment // txHash -> deployment
	maxAge  time.Duration
}

// NewPendingDeploymentTracker creates a new tracker with the specified max age.
// Entries older than maxAge will be removed during cleanup.
func NewPendingDeploymentTracker(maxAge time.Duration) *PendingDeploymentTracker {
	return &PendingDeploymentTracker{
		pending: make(map[string]*PendingDeployment),
		maxAge:  maxAge,
	}
}

// Track adds a pending deployment to the tracker.
// If an entry with the same txHash already exists, it will be overwritten.
func (t *PendingDeploymentTracker) Track(txHash string, deployment *PendingDeployment) {
	if txHash == "" || deployment == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.pending[txHash] = deployment
}

// Get retrieves and removes a pending deployment by tx hash.
// Returns nil if no deployment is found for the given hash.
// This is a "consume" operation - the entry is removed from the tracker.
func (t *PendingDeploymentTracker) Get(txHash string) *PendingDeployment {
	if txHash == "" {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	deployment, ok := t.pending[txHash]
	if !ok {
		return nil
	}

	delete(t.pending, txHash)
	return deployment
}

// Peek retrieves a pending deployment without removing it.
// Returns nil if no deployment is found for the given hash.
func (t *PendingDeploymentTracker) Peek(txHash string) *PendingDeployment {
	if txHash == "" {
		return nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.pending[txHash]
}

// Remove removes a pending deployment by tx hash without returning it.
func (t *PendingDeploymentTracker) Remove(txHash string) {
	if txHash == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.pending, txHash)
}

// Cleanup removes expired pending deployments (older than maxAge).
// Returns the number of entries removed.
func (t *PendingDeploymentTracker) Cleanup() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-t.maxAge)
	removed := 0

	for txHash, deployment := range t.pending {
		if deployment.SubmittedAt.Before(cutoff) {
			delete(t.pending, txHash)
			removed++
		}
	}

	return removed
}

// Size returns the number of pending deployments being tracked.
func (t *PendingDeploymentTracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.pending)
}

// Clear removes all pending deployments.
func (t *PendingDeploymentTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pending = make(map[string]*PendingDeployment)
}
