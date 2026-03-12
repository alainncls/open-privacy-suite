package server

import (
	"strings"
	"sync"
	"time"
)

// DefaultTxOwnershipTTL is how long a txHash→userID mapping is retained.
// 4 hours covers the realistic worst-case finality window on a private network
// while bounding memory. Pending/dropped txs that are never mined age out automatically.
const DefaultTxOwnershipTTL = 4 * time.Hour

type txOwnerEntry struct {
	userID    string
	expiresAt time.Time
}

// TxOwnershipStore maps txHash → userID for transactions submitted through
// this proxy. It allows the response filter to verify ownership even when the
// submitter has no linked ETH address registered.
// Thread-safe. Cleanup is lazy (on every Record call) plus explicit.
type TxOwnershipStore struct {
	mu      sync.RWMutex
	entries map[string]*txOwnerEntry
	ttl     time.Duration
}

// NewTxOwnershipStore creates a new store with the given TTL.
// If ttl is 0, DefaultTxOwnershipTTL is used.
func NewTxOwnershipStore(ttl time.Duration) *TxOwnershipStore {
	if ttl == 0 {
		ttl = DefaultTxOwnershipTTL
	}
	return &TxOwnershipStore{
		entries: make(map[string]*txOwnerEntry),
		ttl:     ttl,
	}
}

// Record stores a txHash → userID mapping. txHash is normalised to lowercase.
// No-ops if either argument is empty. Also runs a lazy sweep of expired entries.
func (s *TxOwnershipStore) Record(txHash, userID string) {
	if txHash == "" || userID == "" {
		return
	}
	key := strings.ToLower(txHash)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.entries[key] = &txOwnerEntry{
		userID:    userID,
		expiresAt: time.Now().Add(s.ttl),
	}
}

// IsOwner returns true iff userID submitted the given txHash and the entry
// has not expired.
func (s *TxOwnershipStore) IsOwner(txHash, userID string) bool {
	if txHash == "" || userID == "" {
		return false
	}
	key := strings.ToLower(txHash)
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return false
	}
	return strings.EqualFold(entry.userID, userID)
}

// Cleanup removes all expired entries. Safe to call periodically if desired.
func (s *TxOwnershipStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked()
}

// Size returns the number of entries (including potentially expired ones not yet swept).
func (s *TxOwnershipStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// sweepLocked removes expired entries. Must be called with write lock held.
func (s *TxOwnershipStore) sweepLocked() int {
	now := time.Now()
	removed := 0
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
			removed++
		}
	}
	return removed
}
