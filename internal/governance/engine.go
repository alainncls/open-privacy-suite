package governance

import (
	"context"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// Applier is responsible for executing the approved mutations.
type Applier interface {
	ApplyGovernanceMutation(ctx context.Context, req *rbac.ApprovalRequest) error
}

// Notifier is responsible for sending alerts for governance events.
type Notifier interface {
	NotifyNewRequest(ctx context.Context, req *rbac.ApprovalRequest) error
	NotifyEscalation(ctx context.Context, req *rbac.ApprovalRequest) error
}

// Engine coordinates the governance flow.
type Engine struct {
	db       *db.DB
	applier  Applier
	notifier Notifier
}

// NewEngine creates a new governance Engine.
func NewEngine(database *db.DB, applier Applier, notifier Notifier) *Engine {
	return &Engine{
		db:       database,
		applier:  applier,
		notifier: notifier,
	}
}
