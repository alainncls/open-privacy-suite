package server

import (
	"github.com/iden3/iden3comm/v2/protocol"
	"privacy-proxy/internal/auth"
)

// SessionManager abstracts the session store operations for dependency injection and testing.
type SessionManager interface {
	// CreateSession creates a new session and returns the session ID.
	// Returns empty string if the store is at capacity.
	CreateSession(authRequest *protocol.AuthorizationRequestMessage) string

	// GetSession retrieves a session by ID.
	// Returns nil if session doesn't exist or has expired.
	GetSession(sessionID string) *auth.Session

	// DeleteSession removes a session.
	DeleteSession(sessionID string)

	// UpdateSession updates an existing session's auth request.
	UpdateSession(sessionID string, authRequest *protocol.AuthorizationRequestMessage) error

	// CompleteSession marks a session as completed with tokens.
	CompleteSession(sessionID, accessToken, refreshToken string) error

	// Stop stops the cleanup goroutine.
	Stop()
}

// RateLimiterInterface abstracts the rate limiter operations for dependency injection and testing.
type RateLimiterInterface interface {
	// CheckAndIncrement checks if a request is allowed and increments counters atomically.
	// Returns (allowed, reason) where reason explains why the request was denied.
	CheckAndIncrement(userID string, rpsLimit, dailyLimit *int) (bool, string)

	// Stop stops the cleanup goroutine.
	Stop()
}

// Verify that concrete types implement the interfaces.
var (
	_ SessionManager       = (*auth.SessionStore)(nil)
	_ RateLimiterInterface = (*RateLimiter)(nil)
)
