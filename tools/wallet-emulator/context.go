package main

import "context"

// emptyContext returns a fresh context for in-process merkle-tree
// operations that don't need cancellation. Keeps the call sites readable.
func emptyContext() context.Context { return context.Background() }
