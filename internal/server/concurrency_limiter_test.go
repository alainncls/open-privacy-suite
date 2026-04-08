package server

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrencyLimiter_AcquireRelease(t *testing.T) {
	cl := NewConcurrencyLimiter(2)

	if !cl.TryAcquire("user1") {
		t.Error("first acquire should succeed")
	}
	if !cl.TryAcquire("user1") {
		t.Error("second acquire should succeed (limit is 2)")
	}
	if cl.TryAcquire("user1") {
		t.Error("third acquire should fail (limit is 2)")
	}

	cl.Release("user1")
	if !cl.TryAcquire("user1") {
		t.Error("acquire after release should succeed")
	}
}

func TestConcurrencyLimiter_PerUser(t *testing.T) {
	cl := NewConcurrencyLimiter(1)

	if !cl.TryAcquire("user1") {
		t.Error("user1 first acquire should succeed")
	}
	if cl.TryAcquire("user1") {
		t.Error("user1 second acquire should fail")
	}
	// Different user should not be affected
	if !cl.TryAcquire("user2") {
		t.Error("user2 should not be affected by user1's limit")
	}

	cl.Release("user1")
	cl.Release("user2")
}

func TestConcurrencyLimiter_Disabled(t *testing.T) {
	cl := NewConcurrencyLimiter(0)

	// Should always succeed when disabled
	for range 100 {
		if !cl.TryAcquire("user1") {
			t.Error("disabled limiter should always allow")
		}
	}
}

func TestConcurrencyLimiter_EmptyUser(t *testing.T) {
	cl := NewConcurrencyLimiter(1)

	// Empty user should always succeed
	if !cl.TryAcquire("") {
		t.Error("empty user should always be allowed")
	}
	if !cl.TryAcquire("") {
		t.Error("empty user should always be allowed (second)")
	}
}

func TestConcurrencyLimiter_Concurrent(t *testing.T) {
	cl := NewConcurrencyLimiter(3)

	// Acquire all 3 slots first so concurrent goroutines will be rejected
	for range 3 {
		if !cl.TryAcquire("user1") {
			t.Fatal("pre-acquire should succeed")
		}
	}

	var acquired atomic.Int32
	var rejected atomic.Int32

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cl.TryAcquire("user1") {
				acquired.Add(1)
				defer cl.Release("user1")
			} else {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()

	// All 3 slots were pre-acquired, so all 20 goroutines should be rejected
	if rejected.Load() != 20 {
		t.Errorf("expected 20 rejections, got %d (acquired %d)", rejected.Load(), acquired.Load())
	}

	// Release pre-acquired slots
	for range 3 {
		cl.Release("user1")
	}
}
