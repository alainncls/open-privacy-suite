package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// SIEMConfig configures the SIEM webhook forwarder.
type SIEMConfig struct {
	WebhookURL      string
	AuthHeader      string
	BatchSize       int
	FlushInterval   time.Duration
	FallbackLogPath string // If set, failed batches are appended here as JSON lines.
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
}

// SIEMForwarder batches audit events and forwards them to a SIEM webhook.
type SIEMForwarder struct {
	cfg    SIEMConfig
	client *http.Client

	mu    sync.Mutex
	batch []SIEMEvent
	stop  chan struct{}
	done  chan struct{}
}

// NewSIEMForwarder creates a new SIEM forwarder. Call Start() to begin flushing.
func NewSIEMForwarder(cfg SIEMConfig) *SIEMForwarder {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 30 * time.Second
	}

	return &SIEMForwarder{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		batch: make([]SIEMEvent, 0, cfg.BatchSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
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
	}
}

const maxRetries = 3

func (s *SIEMForwarder) send(events []SIEMEvent) error {
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
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
	if s.cfg.FallbackLogPath != "" {
		if err := s.writeFallback(events); err != nil {
			log.Printf("ERROR: SIEM flush failed (%v) and fallback write also failed (%v), dropping %d events",
				sendErr, err, len(events))
		} else {
			log.Printf("WARN: SIEM flush failed (%v), wrote %d events to fallback log %s",
				sendErr, len(events), s.cfg.FallbackLogPath)
		}
		return
	}

	// No fallback configured - log at ERROR level with count.
	log.Printf("ERROR: SIEM flush failed (%v), dropping %d events (no fallback path configured)",
		sendErr, len(events))
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
