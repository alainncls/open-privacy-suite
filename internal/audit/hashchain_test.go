package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashChain_DeterministicOutput(t *testing.T) {
	chain1 := NewHashChain("")
	chain2 := NewHashChain("")

	hash1 := chain1.ComputeNext("entry1")
	hash2 := chain2.ComputeNext("entry1")

	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 64) // SHA-256 hex is 64 chars
}

func TestHashChain_ChainReproducibility(t *testing.T) {
	chain1 := NewHashChain("seed-hash")
	chain2 := NewHashChain("seed-hash")

	entries := []string{"first", "second", "third"}
	var hashes1, hashes2 []string

	for _, e := range entries {
		hashes1 = append(hashes1, chain1.ComputeNext(e))
	}
	for _, e := range entries {
		hashes2 = append(hashes2, chain2.ComputeNext(e))
	}

	assert.Equal(t, hashes1, hashes2)
}

func TestHashChain_DifferentInputDifferentHash(t *testing.T) {
	chain1 := NewHashChain("")
	chain2 := NewHashChain("")

	hash1 := chain1.ComputeNext("entry-a")
	hash2 := chain2.ComputeNext("entry-b")

	assert.NotEqual(t, hash1, hash2)
}

func TestHashChain_DifferentSeedDifferentHash(t *testing.T) {
	chain1 := NewHashChain("seed-1")
	chain2 := NewHashChain("seed-2")

	hash1 := chain1.ComputeNext("same-entry")
	hash2 := chain2.ComputeNext("same-entry")

	assert.NotEqual(t, hash1, hash2)
}

func TestHashChain_ManualVerification(t *testing.T) {
	chain := NewHashChain("")

	// Compute first hash: SHA-256("" + "entry1")
	expected1 := sha256hex("" + "entry1")
	actual1 := chain.ComputeNext("entry1")
	assert.Equal(t, expected1, actual1)

	// Compute second hash: SHA-256(hash1 + "entry2")
	expected2 := sha256hex(expected1 + "entry2")
	actual2 := chain.ComputeNext("entry2")
	assert.Equal(t, expected2, actual2)
}

func TestHashChain_ConcurrentSafety(t *testing.T) {
	chain := NewHashChain("")
	var wg sync.WaitGroup

	hashes := make([]string, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hashes[idx] = chain.ComputeNext("concurrent-entry")
		}(i)
	}
	wg.Wait()

	// All hashes should be non-empty and unique (each builds on previous)
	seen := make(map[string]bool)
	for _, h := range hashes {
		require.NotEmpty(t, h)
		require.Len(t, h, 64)
		seen[h] = true
	}
	// With sequential chain, each hash is unique
	assert.Len(t, seen, 100)
}

func TestHashChain_LastHash(t *testing.T) {
	chain := NewHashChain("initial")
	assert.Equal(t, "initial", chain.LastHash())

	hash := chain.ComputeNext("entry")
	assert.Equal(t, hash, chain.LastHash())
}

func sha256hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
