package governance

import (
	"context"
	"log/slog"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// EscalationWorker periodically checks for stale pending approval requests
// and sends escalation notifications via the configured webhook.
type EscalationWorker struct {
	db       *db.DB
	notifier Notifier
	interval time.Duration
	stop     chan struct{}
	done     chan struct{}
}

// NewEscalationWorker creates a new escalation worker. Call Start() to begin.
func NewEscalationWorker(database *db.DB, notifier Notifier, interval time.Duration) *EscalationWorker {
	return &EscalationWorker{
		db:       database,
		notifier: notifier,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start begins the periodic escalation check loop in a goroutine.
func (w *EscalationWorker) Start() {
	go w.run()
}

// Stop signals the escalation loop to stop and waits for it to finish.
func (w *EscalationWorker) Stop() {
	close(w.stop)
	<-w.done
}

func (w *EscalationWorker) run() {
	defer close(w.done)

	if w.interval <= 0 {
		return
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.escalateStaleRequests()
		}
	}
}

func (w *EscalationWorker) escalateStaleRequests() {
	ctx := context.Background()

	staleRequests, err := w.db.ListStaleApprovalRequests(ctx)
	if err != nil {
		slog.Error("escalation: failed to list stale requests", "error", err)
		return
	}

	if len(staleRequests) == 0 {
		return
	}

	slog.Info("escalation: found stale requests", "count", len(staleRequests))

	for _, req := range staleRequests {
		w.escalateRequest(ctx, req)
	}
}

func (w *EscalationWorker) escalateRequest(ctx context.Context, req *rbac.ApprovalRequest) {
	// Send the escalation notification
	if w.notifier != nil {
		if err := w.notifier.NotifyEscalation(ctx, req); err != nil {
			slog.Error("escalation: failed to notify", "request_id", req.ID, "error", err)
			// Don't mark as escalated if notification failed, so we retry next tick.
			return
		}
	}

	// Mark the request as escalated so we don't re-notify.
	now := time.Now()
	if err := w.db.MarkRequestEscalated(ctx, req.ID, now); err != nil {
		slog.Error("escalation: failed to mark escalated", "request_id", req.ID, "error", err)
		return
	}

	slog.Info("escalation: request escalated", "request_id", req.ID, "org_id", req.OrgID)
}
