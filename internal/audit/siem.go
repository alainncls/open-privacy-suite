package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// SIEMEvent represents a normalized audit event for SIEM forwarding.
type SIEMEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"` // "access", "compliance", "rbac"
	CorrelationID string    `json:"correlation_id,omitempty"`
	ActorID       string    `json:"actor_id,omitempty"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource,omitempty"`
	Outcome       string    `json:"outcome"` // "success", "denied", "error"
	Details       string    `json:"details,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	EntryHash     string    `json:"entry_hash,omitempty"`
}

// SIEMConfig holds SIEM forwarder configuration.
type SIEMConfig struct {
	WebhookURL    string
	AuthHeader    string
	BatchSize     int
	FlushInterval time.Duration
}

// SIEMForwarder batches and forwards audit events to a SIEM webhook.
type SIEMForwarder struct {
	config SIEMConfig
	client *http.Client

	mu     sync.Mutex
	batch  []SIEMEvent
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewSIEMForwarder creates and starts a SIEM forwarder.
func NewSIEMForwarder(cfg SIEMConfig) *SIEMForwarder {
	sf := &SIEMForwarder{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		batch:  make([]SIEMEvent, 0, cfg.BatchSize),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go sf.run()
	return sf
}

// Send queues an event for SIEM forwarding. If the batch is full, it triggers an immediate flush.
func (sf *SIEMForwarder) Send(event SIEMEvent) {
	sf.mu.Lock()
	sf.batch = append(sf.batch, event)
	shouldFlush := len(sf.batch) >= sf.config.BatchSize
	sf.mu.Unlock()

	if shouldFlush {
		sf.flush()
	}
}

// Stop flushes any remaining events and stops the forwarder.
func (sf *SIEMForwarder) Stop() {
	close(sf.stopCh)
	<-sf.doneCh
}

func (sf *SIEMForwarder) run() {
	defer close(sf.doneCh)

	ticker := time.NewTicker(sf.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sf.flush()
		case <-sf.stopCh:
			sf.flush() // Final flush
			return
		}
	}
}

func (sf *SIEMForwarder) flush() {
	sf.mu.Lock()
	if len(sf.batch) == 0 {
		sf.mu.Unlock()
		return
	}
	events := sf.batch
	sf.batch = make([]SIEMEvent, 0, sf.config.BatchSize)
	sf.mu.Unlock()

	if err := sf.send(events); err != nil {
		log.Printf("SIEM forward error: %v (%d events dropped)", err, len(events))
	}
}

func (sf *SIEMForwarder) send(events []SIEMEvent) error {
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal SIEM events: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest("POST", sf.config.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if sf.config.AuthHeader != "" {
			req.Header.Set("Authorization", sf.config.AuthHeader)
		}

		resp, err := sf.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// Client error - don't retry
			return lastErr
		}
		// Server error - retry
	}

	return lastErr
}
