package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// SIEMConfig configures the SIEM webhook forwarder.
type SIEMConfig struct {
	WebhookURL      string
	AuthHeader      string
	BatchSize       int
	FlushInterval   time.Duration
	FallbackLogPath string // If set, failed batches are appended here as JSON lines.
	// AllowInsecure relaxes the SSRF guard so HTTP (not just HTTPS) and
	// loopback/private destinations are accepted. Intended for tests and
	// local development only — production callers MUST leave this false so
	// ValidateWebhookURL (strict mode) is applied.
	AllowInsecure bool
}

// SIEMEvent represents an audit event to forward to a SIEM system.
type SIEMEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	ActorID       string    `json:"actor_id,omitempty"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Details       string    `json:"details,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	EntryHash     string    `json:"entry_hash,omitempty"`
	// MatchedVia is "wildcard" when the action method passed the allowlist
	// via a chain-namespace wildcard rather than an explicit entry.
	MatchedVia    string    `json:"matched_via,omitempty"`
	// MatchedPrefix is the wildcard prefix that allowed the method (e.g. "linea_").
	MatchedPrefix string    `json:"matched_prefix,omitempty"`
}

// SIEMForwarder batches audit events and forwards them to a SIEM webhook.
type SIEMForwarder struct {
	cfg    SIEMConfig
	client *http.Client

	mu    sync.Mutex
	batch []SIEMEvent
	stop  chan struct{}
	done  chan struct{}

	// Prometheus metrics (optional, set via SetMetrics)
	batchesTotal       *prometheus.CounterVec
	eventsDroppedTotal prometheus.Counter
}

// SetMetrics configures Prometheus metrics for the SIEM forwarder.
func (s *SIEMForwarder) SetMetrics(batches *prometheus.CounterVec, dropped prometheus.Counter) {
	s.batchesTotal = batches
	s.eventsDroppedTotal = dropped
}

// blockedCIDRs are the IP ranges that must never be used as a SIEM webhook
// destination. Using net.ParseCIDR + subnet.Contains avoids the string-prefix
// pitfall where "172.0.0.1" or "10.io" could bypass or trip a HasPrefix check.
//
// Note: do NOT include IPv4-mapped IPv6 ranges like ::ffff:0:0/96 here.
// Go's net.IPNet.Contains normalises them to IPv4 by taking the last 4 bytes
// of the mask, which turns a /96 IPv6 mask into a /0 IPv4 mask and would
// match every IPv4 address.
var blockedCIDRs = func() []*net.IPNet {
	ranges := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // Link-local / cloud instance metadata (AWS, GCP, Azure)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC-1918 private
		"172.16.0.0/12",  // RFC-1918 private (Docker bridge lives here)
		"192.168.0.0/16", // RFC-1918 private
		"100.64.0.0/10",  // CGNAT / Tailscale (shared address space)
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, err := net.ParseCIDR(r)
		if err != nil {
			panic(fmt.Sprintf("audit: invalid blockedCIDR %q: %v", r, err))
		}
		nets = append(nets, cidr)
	}
	return nets
}()

// ValidateWebhookURL checks that the SIEM webhook URL is safe to use in
// production. It rejects non-HTTPS schemes and private/loopback destinations
// to prevent Server-Side Request Forgery (SSRF). See ValidateWebhookURLForEnv
// for the env-aware variant used in non-prod where HTTP-on-localhost is
// acceptable for development.
//
// IP range checks use net.ParseCIDR + subnet.Contains instead of
// strings.HasPrefix to avoid the pitfalls documented in
// localhost_security_test.go (e.g. "10.io" tripping a prefix check,
// or "172.0.0.1" bypassing the Docker range).
//
// Note: if the host is a domain name (not a bare IP literal), DNS-resolved
// addresses are not checked here — that would require a network call at
// startup. The https requirement and redirect-blocking on the client provide
// additional defence for hostname-based URLs.
func ValidateWebhookURL(rawURL string) error {
	return ValidateWebhookURLForEnv(rawURL, false)
}

// ValidateWebhookURLForEnv runs the SSRF guard with an optional relaxation
// for non-production environments (RD-950).
//
// In strict mode (allowInsecure=false) — the production default — the URL
// must use HTTPS and the host must not resolve to a loopback / RFC-1918 /
// link-local / CGNAT address. This is the only safe configuration for a
// system that POSTs audit data from inside the VPC to an operator-supplied
// destination.
//
// In relaxed mode (allowInsecure=true) HTTP is also accepted, but ONLY when
// the host is a loopback or private-network destination — e.g. an httptest
// server on 127.0.0.1, or a SIEM collector reachable over the Docker bridge
// during local development. Public HTTP destinations are still rejected so
// audit batches never traverse the public internet in cleartext.
func ValidateWebhookURLForEnv(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid SIEM webhook URL: %w", err)
	}

	switch u.Scheme {
	case "https":
		// Always allowed; fall through to the host check below.
	case "http":
		if !allowInsecure {
			return fmt.Errorf("SIEM_WEBHOOK_URL must use https in production, got %q", u.Scheme)
		}
		// Allow HTTP only when the destination is loopback or a private
		// network. Cleartext POST to a public host is still rejected so a
		// misconfigured dev box can't leak audit data to the internet.
		if err := requireLoopbackOrPrivate(u.Hostname()); err != nil {
			return fmt.Errorf("SIEM_WEBHOOK_URL: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("SIEM_WEBHOOK_URL scheme must be http or https, got %q", u.Scheme)
	}

	host := u.Hostname()

	// "localhost" is a hostname alias for loopback; block it by name.
	if host == "localhost" {
		return fmt.Errorf("SIEM_WEBHOOK_URL must not target a loopback address")
	}

	// If the host is an IP literal, run proper CIDR checks.
	if ip := net.ParseIP(host); ip != nil {
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("SIEM_WEBHOOK_URL targets a blocked IP range (%s is in %s)", ip, blocked)
			}
		}
	}

	return nil
}

// requireLoopbackOrPrivate enforces that an HTTP destination is loopback or
// on a private network. Used by ValidateWebhookURLForEnv when running in the
// relaxed mode — cleartext traffic is acceptable on the local box / VPC, but
// not over the public internet.
func requireLoopbackOrPrivate(host string) error {
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name — cannot prove private at validation time without DNS,
		// and we don't want cleartext POSTs to "evil.com". Reject.
		return fmt.Errorf("http scheme is only allowed for loopback or private destinations, got hostname %q", host)
	}
	if ip.IsLoopback() {
		return nil
	}
	for _, private := range allowedHTTPCIDRs {
		if private.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("http scheme is only allowed for loopback or private destinations, got %s", ip)
}

// allowedHTTPCIDRs lists private/loopback IP ranges that may use http://
// when ValidateWebhookURLForEnv is called in relaxed mode (non-production).
// Mirrors the operator-network ranges in server.localhostOnlyMiddleware so
// the two trust boundaries share a single definition of "this is on our
// network, cleartext is acceptable".
var allowedHTTPCIDRs = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"fc00::/7", // IPv6 ULA
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, err := net.ParseCIDR(r)
		if err != nil {
			panic(fmt.Sprintf("audit: invalid allowedHTTPCIDR %q: %v", r, err))
		}
		nets = append(nets, cidr)
	}
	return nets
}()

// NewSIEMForwarder creates a new SIEM forwarder. Call Start() to begin flushing.
//
// The WebhookURL is validated at construction time via
// ValidateWebhookURLForEnv (RD-950) — a malformed or SSRF-prone destination
// makes the forwarder fail fast at startup rather than at the first flush.
// Callers in production must leave SIEMConfig.AllowInsecure=false so HTTPS
// is required and loopback/RFC-1918/link-local destinations are rejected.
func NewSIEMForwarder(cfg SIEMConfig) (*SIEMForwarder, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	if err := ValidateWebhookURLForEnv(cfg.WebhookURL, cfg.AllowInsecure); err != nil {
		return nil, err
	}

	return &SIEMForwarder{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Disallow redirects: a redirect could lead to a private/internal
			// address even when the original URL was validated (open-redirect SSRF).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("redirects not permitted for SIEM webhook")
			},
		},
		batch: make([]SIEMEvent, 0, cfg.BatchSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}, nil
}

// Send queues an event for the next batch. If the batch is full, an immediate flush is triggered.
func (s *SIEMForwarder) Send(event SIEMEvent) {
	s.mu.Lock()
	s.batch = append(s.batch, event)
	full := len(s.batch) >= s.cfg.BatchSize
	s.mu.Unlock()

	if full {
		s.flush()
	}
}

// Start begins the periodic flush loop.
func (s *SIEMForwarder) Start() {
	go s.run()
}

// Stop flushes remaining events and stops the forwarder.
func (s *SIEMForwarder) Stop() {
	close(s.stop)
	<-s.done
}

func (s *SIEMForwarder) run() {
	defer close(s.done)

	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			s.flush()
			return
		case <-ticker.C:
			s.flush()
		}
	}
}

func (s *SIEMForwarder) flush() {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return
	}
	events := s.batch
	s.batch = make([]SIEMEvent, 0, s.cfg.BatchSize)
	s.mu.Unlock()

	if err := s.send(events); err != nil {
		s.handleFailedBatch(events, err)
	} else if s.batchesTotal != nil {
		s.batchesTotal.WithLabelValues("success").Inc()
	}
}

const maxRetries = 3

func (s *SIEMForwarder) send(events []SIEMEvent) error {
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	// RD-950: defence-in-depth re-validation immediately before the outbound
	// request. NewSIEMForwarder already validates the URL at startup, but
	// re-checking here means any future code that mutates s.cfg.WebhookURL
	// (or any new flush path that constructs SIEMForwarder by hand) still
	// has to clear the SSRF guard before reaching net/http. The check is
	// cheap (no DNS, no network) and runs once per batch, not per event.
	if err := ValidateWebhookURLForEnv(s.cfg.WebhookURL, s.cfg.AllowInsecure); err != nil {
		return fmt.Errorf("SIEM webhook URL failed SSRF guard: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest(http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if s.cfg.AuthHeader != "" {
			req.Header.Set("Authorization", s.cfg.AuthHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("SIEM webhook returned status %d", resp.StatusCode)
	}

	return fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}

// handleFailedBatch handles events that could not be sent after all retries.
// M4 fix: if FallbackLogPath is configured, write events to a local file so
// operators can recover them manually. The batch is always dropped from memory
// (no infinite retry) regardless of fallback success.
func (s *SIEMForwarder) handleFailedBatch(events []SIEMEvent, sendErr error) {
	if s.batchesTotal != nil {
		s.batchesTotal.WithLabelValues("error").Inc()
	}
	if s.eventsDroppedTotal != nil {
		s.eventsDroppedTotal.Add(float64(len(events)))
	}

	if s.cfg.FallbackLogPath != "" {
		if err := s.writeFallback(events); err != nil {
			slog.Error("SIEM flush failed and fallback write also failed, dropping events", "send_error", sendErr, "fallback_error", err, "count", len(events))
		} else {
			slog.Warn("SIEM flush failed, wrote events to fallback log", "error", sendErr, "count", len(events), "fallback_path", s.cfg.FallbackLogPath)
		}
		return
	}

	// No fallback configured - log at ERROR level with count.
	slog.Error("SIEM flush failed, dropping events (no fallback path configured)", "error", sendErr, "count", len(events))
}

// writeFallback appends events as JSON lines to the fallback log file.
func (s *SIEMForwarder) writeFallback(events []SIEMEvent) error {
	f, err := os.OpenFile(s.cfg.FallbackLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open fallback log: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("write event to fallback log: %w", err)
		}
	}
	return nil
}
