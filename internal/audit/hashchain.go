package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// HashChain provides cryptographic integrity for audit log entries.
// Each entry's hash is computed as SHA-256(previousHash | entryContent),
// creating a chain where tampering with any entry invalidates all subsequent hashes.
type HashChain struct {
	mu       sync.Mutex
	lastHash string
}

// NewHashChain creates a new hash chain seeded with the last known hash from the database.
// If lastKnownHash is empty (first entry or empty DB), the chain starts with a zero hash.
func NewHashChain(lastKnownHash string) *HashChain {
	return &HashChain{
		lastHash: lastKnownHash,
	}
}

// ComputeNext computes the hash for the next audit entry and advances the chain.
// The hash is SHA-256(previousHash | entryContent).
// This method is thread-safe.
func (h *HashChain) ComputeNext(entryContent string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	hasher := sha256.New()
	hasher.Write([]byte(h.lastHash))
	hasher.Write([]byte(entryContent))
	hash := hex.EncodeToString(hasher.Sum(nil))

	h.lastHash = hash
	return hash
}

// LastHash returns the current tail hash of the chain.
func (h *HashChain) LastHash() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastHash
}
