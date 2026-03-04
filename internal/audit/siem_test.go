package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSIEM_SuccessfulSendClearsBatch(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []SIEMEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			t.Errorf("decode error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int64(len(events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     100,
		FlushInterval: 50 * time.Millisecond,
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "eth_sendTransaction", Outcome: "success"})

	fwd.Start()
	time.Sleep(120 * time.Millisecond)
	fwd.Stop()

	if received.Load() != 2 {
		t.Fatalf("expected 2 events received by SIEM, got %d", received.Load())
	}

	// After stop, internal batch should be empty.
	fwd.mu.Lock()
	remaining := len(fwd.batch)
	fwd.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected empty batch after stop, got %d", remaining)
	}
}

func TestSIEM_FailedSendWithFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fallbackPath := filepath.Join(t.TempDir(), "fallback.jsonl")

	fwd := NewSIEMForwarder(SIEMConfig{
		WebhookURL:      srv.URL,
		BatchSize:        100,
		FlushInterval:    50 * time.Millisecond,
		FallbackLogPath:  fallbackPath,
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "eth_getBalance", Outcome: "success"})

	fwd.Start()
	// Wait for flush + retries (3 retries with backoff: 0s + 1s + 2s = ~3s).
	time.Sleep(5 * time.Second)
	fwd.Stop()

	// Check fallback file was written.
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		t.Fatalf("failed to read fallback file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected fallback file to contain events")
	}

	// Parse each JSON line.
	lines := 0
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var event SIEMEvent
		if err := dec.Decode(&event); err != nil {
			t.Fatalf("failed to decode fallback event: %v", err)
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("expected 2 events in fallback file, got %d", lines)
	}
}

func TestSIEM_FailedSendWithoutFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fwd := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     100,
		FlushInterval: 50 * time.Millisecond,
		// No FallbackLogPath - events will be dropped with ERROR log.
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})

	fwd.Start()
	time.Sleep(5 * time.Second)
	fwd.Stop()

	// No crash, events dropped. The ERROR log is printed but we cannot easily
	// capture log output in this test without a custom logger.
	fwd.mu.Lock()
	remaining := len(fwd.batch)
	fwd.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected empty batch after stop, got %d", remaining)
	}
}

func TestSIEM_StopFlushesPending(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []SIEMEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int64(len(events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     100,
		FlushInterval: 1 * time.Hour, // will not tick during test
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})
	fwd.Start()

	// Stop should flush the pending event.
	fwd.Stop()

	if received.Load() != 1 {
		t.Fatalf("expected 1 event flushed on Stop(), got %d", received.Load())
	}
}

func TestSIEM_BatchSizeTrigger(t *testing.T) {
	var flushes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flushes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     3,
		FlushInterval: 1 * time.Hour, // will not tick during test
	})

	fwd.Start()

	// Adding 3 events should trigger an immediate flush (batch full).
	fwd.Send(SIEMEvent{Action: "a", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "b", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "c", Outcome: "success"})

	// Give the flush a moment to complete.
	time.Sleep(100 * time.Millisecond)

	if flushes.Load() < 1 {
		t.Fatal("expected at least 1 flush when batch size reached")
	}

	fwd.Stop()
}

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid
		{"valid https URL", "https://siem.example.com/ingest", false},
		{"172.32.x allowed - outside private range", "https://172.32.0.1/ingest", false},

		// Scheme
		{"http rejected", "http://siem.example.com/ingest", true},
		{"invalid URL rejected", "://bad-url", true},

		// Loopback
		{"localhost rejected", "https://localhost/ingest", true},
		{"127.0.0.1 rejected", "https://127.0.0.1/ingest", true},
		{"127.255.255.255 rejected - whole /8 blocked", "https://127.255.255.255/ingest", true},

		// Link-local / cloud metadata
		{"169.254.169.254 rejected - AWS metadata", "https://169.254.169.254/latest/meta-data/", true},
		{"169.254.0.1 rejected - link-local range start", "https://169.254.0.1/ingest", true},

		// RFC-1918 private ranges - correct CIDR boundaries, not string prefix
		{"10.0.0.1 rejected", "https://10.0.0.1/ingest", true},
		{"10.255.255.255 rejected - end of /8", "https://10.255.255.255/ingest", true},
		{"192.168.1.1 rejected", "https://192.168.1.1/ingest", true},
		{"172.16.0.1 rejected - start of Docker /12", "https://172.16.0.1/ingest", true},
		{"172.31.255.255 rejected - end of Docker /12", "https://172.31.255.255/ingest", true},

		// Pitfall: string-prefix matching would wrongly block/allow these
		{"172.0.0.1 allowed - outside 172.16/12 (HasPrefix pitfall)", "https://172.0.0.1/ingest", false},
		{"172.15.255.255 allowed - just below 172.16/12", "https://172.15.255.255/ingest", false},

		// Domain names that look like IPs are NOT blocked (host is not a bare IP)
		// This documents the known limitation: DNS resolution is not performed at validation time.
		{"10.io domain allowed - not a bare IP", "https://10.io/ingest", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
