package tracer

import (
	"context"
	"strings"
	"time"
)

// RuntimeTracer provides integrated runtime tracing with caching.
// It combines the Tracer (for debug_traceCall) and TraceCache.
type RuntimeTracer struct {
	tracer  *Tracer
	cache   *TraceCache
	enabled bool
	tiered  bool // If true, skip trace for known addresses
}

// RuntimeTracerConfig configures the RuntimeTracer.
type RuntimeTracerConfig struct {
	NodeURL       string
	Enabled       bool
	CacheTTL      time.Duration
	Timeout       time.Duration
	TieredEnabled bool
}

// NewRuntimeTracer creates a new RuntimeTracer.
func NewRuntimeTracer(cfg RuntimeTracerConfig) *RuntimeTracer {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 10 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	return &RuntimeTracer{
		tracer:  NewTracer(cfg.NodeURL, cfg.Timeout),
		cache:   NewTraceCache(cfg.CacheTTL, cfg.CacheTTL/2),
		enabled: cfg.Enabled,
		tiered:  cfg.TieredEnabled,
	}
}

// IsEnabled returns whether runtime tracing is enabled.
func (rt *RuntimeTracer) IsEnabled() bool {
	return rt.enabled
}

// IsTieredEnabled returns whether tiered validation is enabled.
// When tiered validation is enabled, known org-owned addresses skip tracing.
func (rt *RuntimeTracer) IsTieredEnabled() bool {
	return rt.tiered
}

// TraceTransaction traces a transaction and returns all call targets.
// It uses the cache to avoid redundant traces for identical transactions.
func (rt *RuntimeTracer) TraceTransaction(
	ctx context.Context,
	from, to, data, value string,
) (*TraceResult, error) {
	if !rt.enabled {
		return nil, nil
	}

	// Normalize inputs for cache key
	from = strings.ToLower(strings.TrimSpace(from))
	to = strings.ToLower(strings.TrimSpace(to))
	data = strings.ToLower(strings.TrimSpace(data))
	value = strings.TrimSpace(value)

	// Check cache first
	if cached := rt.cache.Get(from, to, data, value, "latest"); cached != nil {
		return cached, nil
	}

	// Perform trace
	result, err := rt.tracer.TraceCall(ctx, from, to, data, value, "latest")
	if err != nil {
		return nil, err
	}

	// Cache the result
	rt.cache.Set(from, to, data, value, "latest", result)

	return result, nil
}

// Stop gracefully stops the RuntimeTracer.
func (rt *RuntimeTracer) Stop() {
	if rt.cache != nil {
		rt.cache.Stop()
	}
}
