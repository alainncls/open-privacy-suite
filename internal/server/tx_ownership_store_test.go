package server

import (
	"testing"
	"time"
)

func TestTxOwnershipStore_RecordAndIsOwner(t *testing.T) {
	s := NewTxOwnershipStore(time.Hour)
	s.Record("0xabc123", "user-1")

	if !s.IsOwner("0xabc123", "user-1") {
		t.Error("expected IsOwner true for recorded entry")
	}
}

func TestTxOwnershipStore_CaseInsensitiveHash(t *testing.T) {
	s := NewTxOwnershipStore(time.Hour)
	s.Record("0xABC123", "user-1")

	if !s.IsOwner("0xabc123", "user-1") {
		t.Error("expected IsOwner true regardless of txHash case")
	}
	if !s.IsOwner("0xABC123", "user-1") {
		t.Error("expected IsOwner true regardless of txHash case (uppercase query)")
	}
}

func TestTxOwnershipStore_WrongUser(t *testing.T) {
	s := NewTxOwnershipStore(time.Hour)
	s.Record("0xabc123", "user-1")

	if s.IsOwner("0xabc123", "user-2") {
		t.Error("expected IsOwner false for different user")
	}
}

func TestTxOwnershipStore_ExpiredEntry(t *testing.T) {
	s := NewTxOwnershipStore(1 * time.Millisecond)
	s.Record("0xabc123", "user-1")
	time.Sleep(5 * time.Millisecond)

	if s.IsOwner("0xabc123", "user-1") {
		t.Error("expected IsOwner false for expired entry")
	}
}

func TestTxOwnershipStore_EmptyInputsNoOp(t *testing.T) {
	s := NewTxOwnershipStore(time.Hour)
	s.Record("", "user-1")
	s.Record("0xabc123", "")

	if s.IsOwner("", "user-1") {
		t.Error("empty txHash must return false")
	}
	if s.IsOwner("0xabc123", "") {
		t.Error("empty userID must return false")
	}
	if s.Size() != 0 {
		t.Errorf("expected 0 entries, got %d", s.Size())
	}
}

func TestTxOwnershipStore_Cleanup(t *testing.T) {
	s := NewTxOwnershipStore(1 * time.Millisecond)
	s.Record("0xhash1", "user-1")
	s.Record("0xhash2", "user-2")
	time.Sleep(5 * time.Millisecond)

	removed := s.Cleanup()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if s.Size() != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", s.Size())
	}
}

func TestTxOwnershipStore_LazySweepOnRecord(t *testing.T) {
	s := NewTxOwnershipStore(1 * time.Millisecond)
	s.Record("0xold", "user-1")
	time.Sleep(5 * time.Millisecond)
	// Adding a new entry triggers sweep of expired ones
	s.Record("0xnew", "user-2")

	if s.Size() != 1 {
		t.Errorf("expected 1 live entry after lazy sweep, got %d", s.Size())
	}
}

func TestTxOwnershipStore_DefaultTTL(t *testing.T) {
	s := NewTxOwnershipStore(0) // 0 = use default
	if s.ttl != DefaultTxOwnershipTTL {
		t.Errorf("expected default TTL %v, got %v", DefaultTxOwnershipTTL, s.ttl)
	}
}
