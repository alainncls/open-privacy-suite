package server

import (
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// State store tests — session capacity, cleanup, concurrency, azure state.
// No DB needed — these test in-memory stores directly.

func TestResilience_SessionStore_CapacityEnforced(t *testing.T) {
	maxSessions := 100
	store := auth.NewSessionStoreWithMax(10*time.Minute, 1*time.Hour, maxSessions)
	defer store.Stop()

	for i := 0; i < maxSessions; i++ {
		id := store.CreateSession(nil)
		assert.NotEmpty(t, id, "session %d should be created", i)
	}

	id := store.CreateSession(nil)
	assert.Empty(t, id, "session store must reject when at capacity")
}

func TestResilience_SessionStore_CleanupReclaims(t *testing.T) {
	store := auth.NewSessionStoreWithMax(50*time.Millisecond, 25*time.Millisecond, 10)
	defer store.Stop()

	for i := 0; i < 10; i++ {
		id := store.CreateSession(nil)
		require.NotEmpty(t, id)
	}

	assert.Empty(t, store.CreateSession(nil), "should be at capacity")

	time.Sleep(150 * time.Millisecond)

	id := store.CreateSession(nil)
	assert.NotEmpty(t, id, "cleanup should have reclaimed expired sessions")
}

func TestResilience_SessionStore_ConcurrentCreation(t *testing.T) {
	store := auth.NewSessionStoreWithMax(10*time.Minute, 1*time.Hour, 500)
	defer store.Stop()

	var wg sync.WaitGroup
	results := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = store.CreateSession(nil)
		}(i)
	}
	wg.Wait()

	created := 0
	for _, r := range results {
		if r != "" {
			created++
		}
	}

	assert.LessOrEqual(t, created, 550,
		"concurrent creation must be bounded near max sessions (some slack for atomic races)")
	assert.Greater(t, 1000-created, 400,
		"most excess sessions must be rejected")
}

func TestResilience_AzureStateStore_CleanupExpired(t *testing.T) {
	store := NewAzureStateStore(50*time.Millisecond, 25*time.Millisecond)
	defer store.Stop()

	state, _ := store.Create()
	time.Sleep(100 * time.Millisecond)

	_, ok := store.Consume(state)
	assert.False(t, ok, "expired state must not be consumable")
}

func TestResilience_AzureStateStore_SingleUse(t *testing.T) {
	store := NewAzureStateStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	state, nonce := store.Create()

	gotNonce, ok := store.Consume(state)
	assert.True(t, ok)
	assert.Equal(t, nonce, gotNonce)

	_, ok = store.Consume(state)
	assert.False(t, ok, "state token must be single-use")
}
