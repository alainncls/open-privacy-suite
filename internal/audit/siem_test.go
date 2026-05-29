package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mustNewForwarder is a test helper that builds a SIEMForwarder pointing at a
// loopback httptest server. AllowInsecure is set because httptest.NewServer
// gives back an http://127.0.0.1:... URL which the production SSRF guard
// (correctly) rejects. The relaxed mode used here mirrors what server.go
// configures when ENVIRONMENT != "production" (RD-950).
func mustNewForwarder(t *testing.T, cfg SIEMConfig) *SIEMForwarder {
	t.Helper()
	cfg.AllowInsecure = true
	fwd, err := NewSIEMForwarder(cfg)
	if err != nil {
		t.Fatalf("NewSIEMForwarder: %v", err)
	}
	return fwd
}

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

	fwd := mustNewForwarder(t, SIEMConfig{
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

	fwd := mustNewForwarder(t, SIEMConfig{
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

	fwd := mustNewForwarder(t, SIEMConfig{
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

	fwd := mustNewForwarder(t, SIEMConfig{
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

	fwd := mustNewForwarder(t, SIEMConfig{
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

		// IPv6 loopback
		{"[::1] rejected - IPv6 loopback", "https://[::1]/ingest", true},

		// Link-local / cloud metadata
		{"169.254.169.254 rejected - AWS metadata", "https://169.254.169.254/latest/meta-data/", true},
		{"169.254.0.1 rejected - link-local range start", "https://169.254.0.1/ingest", true},

		// IPv6 link-local
		{"[fe80::1] rejected - IPv6 link-local", "https://[fe80::1]/ingest", true},

		// RFC-1918 private ranges - correct CIDR boundaries, not string prefix
		{"10.0.0.1 rejected", "https://10.0.0.1/ingest", true},
		{"10.255.255.255 rejected - end of /8", "https://10.255.255.255/ingest", true},
		{"192.168.1.1 rejected", "https://192.168.1.1/ingest", true},
		{"172.16.0.1 rejected - start of Docker /12", "https://172.16.0.1/ingest", true},
		{"172.31.255.255 rejected - end of Docker /12", "https://172.31.255.255/ingest", true},

		// CGNAT / Tailscale (RFC-6598 shared address space)
		{"100.64.0.1 rejected - CGNAT/Tailscale start", "https://100.64.0.1/ingest", true},

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

// TestValidateWebhookURLForEnv covers the env-aware variant added for RD-950.
// In production (allowInsecure=false) the behaviour is identical to
// ValidateWebhookURL — see TestValidateWebhookURL above. The cases below
// document the non-prod relaxation: HTTP is accepted but only when the host
// is loopback or RFC-1918, never for public destinations.
func TestValidateWebhookURLForEnv(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
		wantErrSubstr string // optional: substring to assert in the error message
	}{
		// Non-prod: HTTP on loopback/private is OK, mirrors how local
		// docker-compose dev points the SIEM at an httptest stub.
		{"non-prod http loopback allowed", "http://127.0.0.1:9000/ingest", true, false, ""},
		{"non-prod http localhost allowed", "http://localhost:9000/ingest", true, false, ""},
		{"non-prod http RFC-1918 allowed", "http://10.1.2.3/ingest", true, false, ""},
		{"non-prod http Docker bridge allowed", "http://172.18.0.5/ingest", true, false, ""},
		{"non-prod https public still allowed", "https://siem.example.com/ingest", true, false, ""},

		// Non-prod: HTTP on a public destination MUST still be rejected.
		// We don't ever want audit batches in cleartext over the public
		// internet, even from a dev box.
		{"non-prod http public rejected", "http://siem.example.com/ingest", true, true, "loopback or private"},
		{"non-prod http public IP rejected", "http://8.8.8.8/ingest", true, true, "loopback or private"},

		// Non-prod: cloud-metadata IP is still rejected — link-local is
		// neither loopback nor private and is the canonical SSRF target.
		{"non-prod http 169.254.169.254 rejected (AWS metadata)", "http://169.254.169.254/latest/meta-data/", true, true, "loopback or private"},

		// Prod: every loopback / private / link-local rejection from
		// TestValidateWebhookURL must still apply. A representative sample
		// here keeps the contract explicit; the exhaustive list lives above.
		{"prod http rejected", "http://siem.example.com/ingest", false, true, "https"},
		{"prod localhost rejected", "https://localhost/ingest", false, true, "loopback"},
		{"prod 127.0.0.1 rejected", "https://127.0.0.1/ingest", false, true, "blocked IP range"},
		{"prod 10.0.0.1 rejected", "https://10.0.0.1/ingest", false, true, "blocked IP range"},
		{"prod 192.168.1.1 rejected", "https://192.168.1.1/ingest", false, true, "blocked IP range"},
		{"prod 172.16.0.1 rejected", "https://172.16.0.1/ingest", false, true, "blocked IP range"},
		{"prod 169.254.169.254 rejected (AWS metadata)", "https://169.254.169.254/latest/meta-data/", false, true, "blocked IP range"},
		{"prod [::1] rejected (IPv6 loopback)", "https://[::1]/ingest", false, true, "blocked IP range"},
		{"prod [fe80::1] rejected (IPv6 link-local)", "https://[fe80::1]/ingest", false, true, "blocked IP range"},
		{"prod public https allowed", "https://siem.example.com/ingest", false, false, ""},

		// Garbage schemes are rejected in both modes — we only know what
		// to do with http/https.
		{"non-prod file scheme rejected", "file:///etc/passwd", true, true, "scheme"},
		{"prod gopher scheme rejected", "gopher://siem.example.com/", false, true, "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURLForEnv(tt.url, tt.allowInsecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateWebhookURLForEnv(%q, allowInsecure=%v) error = %v, wantErr %v",
					tt.url, tt.allowInsecure, err, tt.wantErr)
			}
			if tt.wantErr && tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("ValidateWebhookURLForEnv(%q, allowInsecure=%v) error = %v, want substring %q",
					tt.url, tt.allowInsecure, err, tt.wantErrSubstr)
			}
		})
	}
}

// TestNewSIEMForwarder_RejectsBadURL verifies the defence-in-depth wiring
// added for RD-950: NewSIEMForwarder now refuses to construct a forwarder
// whose WebhookURL would fail the SSRF guard, so a misconfiguration fails
// fast at startup rather than at the first flush.
func TestNewSIEMForwarder_RejectsBadURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
	}{
		{"prod rejects http", "http://siem.example.com/ingest", false},
		{"prod rejects loopback", "https://127.0.0.1/ingest", false},
		{"prod rejects AWS metadata", "https://169.254.169.254/", false},
		{"prod rejects private", "https://10.1.2.3/ingest", false},
		{"non-prod rejects http public", "http://siem.example.com/ingest", true},
		{"non-prod rejects AWS metadata", "http://169.254.169.254/", true},
		{"both reject malformed", "://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, err := NewSIEMForwarder(SIEMConfig{
				WebhookURL:    tt.url,
				BatchSize:     10,
				FlushInterval: time.Second,
				AllowInsecure: tt.allowInsecure,
			})
			if err == nil {
				t.Fatalf("NewSIEMForwarder(%q, allowInsecure=%v) returned nil error, want failure",
					tt.url, tt.allowInsecure)
			}
			if fwd != nil {
				t.Errorf("NewSIEMForwarder(%q): expected nil forwarder on error, got %#v", tt.url, fwd)
			}
		})
	}
}

// TestNewSIEMForwarder_AcceptsGoodURL is the positive case — a real-shaped
// production URL (public HTTPS) must construct cleanly.
func TestNewSIEMForwarder_AcceptsGoodURL(t *testing.T) {
	fwd, err := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    "https://siem.example.com/ingest",
		BatchSize:     10,
		FlushInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSIEMForwarder: %v", err)
	}
	if fwd == nil {
		t.Fatal("NewSIEMForwarder returned nil forwarder with nil error")
	}
}
