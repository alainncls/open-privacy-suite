package auth

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
)

// DefaultMaxSessions is the default maximum number of concurrent sessions.
const DefaultMaxSessions = 10000

// ErrSessionStoreFull is returned when the session store is at capacity.
var ErrSessionStoreFull = errors.New("session store is at capacity")

// Session represents an authentication session
type Session struct {
	mu          sync.Mutex
	ID          string
	AuthRequest *protocol.AuthorizationRequestMessage
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// Completion fields - set when wallet callback succeeds
	Completed    bool
	AccessToken  string
	RefreshToken string
	CompletedAt  time.Time
}

// SessionStore manages authentication sessions
// Uses in-memory storage with TTL cleanup
// Thread-safe using sync.Map
type SessionStore struct {
	sessions    sync.Map // map[string]*Session
	wg          sync.WaitGroup
	ttl         time.Duration
	stopCh      chan struct{}
	maxSessions int
	count       atomic.Int64 // Current number of sessions
}

// NewSessionStore creates a new session store with TTL
// cleanupInterval: how often to run cleanup (e.g., 1 minute)
// sessionTTL: how long sessions are valid (e.g., 10 minutes)
func NewSessionStore(sessionTTL, cleanupInterval time.Duration) *SessionStore {
	return NewSessionStoreWithMax(sessionTTL, cleanupInterval, DefaultMaxSessions)
}

// NewSessionStoreWithMax creates a new session store with TTL and max sessions limit.
func NewSessionStoreWithMax(sessionTTL, cleanupInterval time.Duration, maxSessions int) *SessionStore {
	store := &SessionStore{
		ttl:         sessionTTL,
		stopCh:      make(chan struct{}),
		maxSessions: maxSessions,
	}

	// Start cleanup goroutine
	store.wg.Add(1)
	go store.cleanup(cleanupInterval)

	return store
}

// CreateSession creates a new session and returns the session ID.
// Returns empty string if the store is at capacity.
func (s *SessionStore) CreateSession(authRequest *protocol.AuthorizationRequestMessage) string {
	// Check capacity before creating
	if s.maxSessions > 0 && s.count.Load() >= int64(s.maxSessions) {
		return "" // At capacity
	}

	sessionID := uuid.New().String()
	now := time.Now()

	session := &Session{
		ID:          sessionID,
		AuthRequest: authRequest,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
	}

	s.sessions.Store(sessionID, session)
	s.count.Add(1)
	return sessionID
}

// GetSession retrieves a session by ID
// Returns nil if session doesn't exist or has expired
func (s *SessionStore) GetSession(sessionID string) *Session {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return nil
	}

	session := value.(*Session)

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		s.deleteSession(sessionID)
		return nil
	}

	return session
}

// DeleteSession removes a session
func (s *SessionStore) DeleteSession(sessionID string) {
	s.deleteSession(sessionID)
}

// deleteSession is the internal delete that tracks the count
func (s *SessionStore) deleteSession(sessionID string) {
	if _, loaded := s.sessions.LoadAndDelete(sessionID); loaded {
		s.count.Add(-1)
	}
}

// UpdateSession updates an existing session's auth request
func (s *SessionStore) UpdateSession(sessionID string, authRequest *protocol.AuthorizationRequestMessage) error {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	session := value.(*Session)
	session.mu.Lock()
	session.AuthRequest = authRequest
	s.sessions.Store(sessionID, session)
	session.mu.Unlock()
	return nil
}

// CompleteSession marks a session as completed with tokens
// Keeps the session alive for a short time so the frontend can poll for completion
func (s *SessionStore) CompleteSession(sessionID, accessToken, refreshToken string) error {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	session := value.(*Session)
	session.mu.Lock()
	session.Completed = true
	session.AccessToken = accessToken
	session.RefreshToken = refreshToken
	session.CompletedAt = time.Now()
	// Extend expiry so frontend has time to poll and get the tokens
	session.ExpiresAt = time.Now().Add(2 * time.Minute)
	s.sessions.Store(sessionID, session)
	session.mu.Unlock()
	return nil
}

// cleanup periodically removes expired sessions
func (s *SessionStore) cleanup(interval time.Duration) {
	defer s.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(key, value any) bool {
				session := value.(*Session)
				if now.After(session.ExpiresAt) {
					s.deleteSession(key.(string))
				}
				return true
			})
		case <-s.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (s *SessionStore) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// Count returns the current number of sessions.
func (s *SessionStore) Count() int64 {
	return s.count.Load()
}
