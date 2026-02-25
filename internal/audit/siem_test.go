package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSIEMForwarder_BatchFlush(t *testing.T) {
	var received []SIEMEvent
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var events []SIEMEvent
		json.Unmarshal(body, &events)
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sf := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    server.URL,
		BatchSize:     3,
		FlushInterval: 1 * time.Hour, // won't fire
	})

	// Send 3 events (triggers batch flush)
	for i := 0; i < 3; i++ {
		sf.Send(SIEMEvent{
			EventType: "access",
			Action:    "rpc_call",
			Outcome:   "success",
		})
	}

	// Allow time for flush
	time.Sleep(200 * time.Millisecond)
	sf.Stop()

	mu.Lock()
	assert.Len(t, received, 3)
	mu.Unlock()
}

func TestSIEMForwarder_FlushInterval(t *testing.T) {
	var received []SIEMEvent
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var events []SIEMEvent
		json.Unmarshal(body, &events)
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sf := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    server.URL,
		BatchSize:     100, // large batch
		FlushInterval: 100 * time.Millisecond,
	})

	sf.Send(SIEMEvent{EventType: "access", Action: "test"})

	// Wait for interval flush
	time.Sleep(300 * time.Millisecond)
	sf.Stop()

	mu.Lock()
	assert.Len(t, received, 1)
	mu.Unlock()
}

func TestSIEMForwarder_RetryOnServerError(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sf := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    server.URL,
		BatchSize:     1,
		FlushInterval: 1 * time.Hour,
	})

	sf.Send(SIEMEvent{EventType: "access", Action: "test"})

	// Allow retries to complete (retry delays: 0s, 1s, 2s)
	time.Sleep(5 * time.Second)
	sf.Stop()

	assert.Equal(t, int32(3), attempts.Load())
}

func TestSIEMForwarder_AuthHeader(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sf := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    server.URL,
		AuthHeader:    "Bearer test-token-123",
		BatchSize:     1,
		FlushInterval: 1 * time.Hour,
	})

	sf.Send(SIEMEvent{EventType: "access"})
	time.Sleep(200 * time.Millisecond)
	sf.Stop()

	assert.Equal(t, "Bearer test-token-123", receivedAuth)
}

func TestSIEMForwarder_GracefulStop(t *testing.T) {
	var received []SIEMEvent
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var events []SIEMEvent
		json.Unmarshal(body, &events)
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sf := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    server.URL,
		BatchSize:     100,
		FlushInterval: 1 * time.Hour,
	})

	// Send events that won't trigger batch flush
	sf.Send(SIEMEvent{EventType: "access", Action: "pending1"})
	sf.Send(SIEMEvent{EventType: "access", Action: "pending2"})

	// Stop should flush remaining events
	sf.Stop()

	mu.Lock()
	require.Len(t, received, 2)
	mu.Unlock()
}

func TestSIEMForwarder_NoRetryOnClientError(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	sf := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    server.URL,
		BatchSize:     1,
		FlushInterval: 1 * time.Hour,
	})

	sf.Send(SIEMEvent{EventType: "access"})
	time.Sleep(200 * time.Millisecond)
	sf.Stop()

	// Should only attempt once for 4xx errors
	assert.Equal(t, int32(1), attempts.Load())
}
