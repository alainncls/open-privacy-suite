package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/google/uuid"
)

// Session represents an authentication session
type Session struct {
	ID            string
	AuthRequest   *protocol.AuthorizationRequestMessage
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// SessionStore manages authentication sessions
// Uses in-memory storage with TTL cleanup
// Thread-safe using sync.Map
type SessionStore struct {
	sessions sync.Map // map[string]*Session
	ttl      time.Duration
	stopCh   chan struct{}
}

// NewSessionStore creates a new session store with TTL
// cleanupInterval: how often to run cleanup (e.g., 1 minute)
// sessionTTL: how long sessions are valid (e.g., 10 minutes)
func NewSessionStore(sessionTTL, cleanupInterval time.Duration) *SessionStore {
	store := &SessionStore{
		ttl:    sessionTTL,
		stopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanup(cleanupInterval)

	return store
}

// CreateSession creates a new session and returns the session ID
func (s *SessionStore) CreateSession(authRequest *protocol.AuthorizationRequestMessage) string {
	sessionID := uuid.New().String()
	now := time.Now()
	
	session := &Session{
		ID:          sessionID,
		AuthRequest: authRequest,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
	}

	s.sessions.Store(sessionID, session)
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
		s.sessions.Delete(sessionID)
		return nil
	}

	return session
}

// DeleteSession removes a session
func (s *SessionStore) DeleteSession(sessionID string) {
	s.sessions.Delete(sessionID)
}

// UpdateSession updates an existing session's auth request
func (s *SessionStore) UpdateSession(sessionID string, authRequest *protocol.AuthorizationRequestMessage) error {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	session := value.(*Session)
	session.AuthRequest = authRequest
	s.sessions.Store(sessionID, session)
	return nil
}

// cleanup periodically removes expired sessions
func (s *SessionStore) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(key, value interface{}) bool {
				session := value.(*Session)
				if now.After(session.ExpiresAt) {
					s.sessions.Delete(key)
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
}
