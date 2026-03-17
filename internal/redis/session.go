package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"privacy-proxy/internal/auth"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/redis/go-redis/v9"
)

const (
	// sessionKeyPrefix is the Redis key prefix for auth sessions.
	sessionKeyPrefix = "pp:session:"

	// defaultSessionScanCount is the COUNT hint for SCAN operations.
	defaultSessionScanCount = 100
)

// SessionStore is a Redis-backed implementation of the SessionManager interface.
// It stores auth sessions as JSON values with Redis TTL for automatic expiry,
// replacing the in-memory sync.Map-based store.
type SessionStore struct {
	client      *redis.Client
	ttl         time.Duration
	maxSessions int
}

// NewSessionStore creates a new Redis-backed session store.
func NewSessionStore(client *redis.Client, sessionTTL time.Duration, maxSessions int) *SessionStore {
	return &SessionStore{
		client:      client,
		ttl:         sessionTTL,
		maxSessions: maxSessions,
	}
}

// CreateSession creates a new session and returns the session ID.
// Returns empty string if the store is at capacity.
func (s *SessionStore) CreateSession(authRequest *protocol.AuthorizationRequestMessage) string {
	ctx := context.Background()

	// Check capacity via SCAN count (approximate, same as in-memory store).
	if s.maxSessions > 0 && s.Count() >= int64(s.maxSessions) {
		return ""
	}

	sessionID := uuid.New().String()
	now := time.Now()

	session := &auth.Session{
		ID:          sessionID,
		AuthRequest: authRequest,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
	}

	data, err := json.Marshal(session)
	if err != nil {
		slog.Error("redis session store: failed to marshal session", "error", err)
		return ""
	}

	key := sessionKeyPrefix + sessionID
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		slog.Error("redis session store: failed to store session", "error", err)
		return ""
	}

	return sessionID
}

// GetSession retrieves a session by ID.
// Returns nil if session doesn't exist or has expired.
func (s *SessionStore) GetSession(sessionID string) *auth.Session {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis session store: failed to get session", "error", err)
		}
		return nil
	}

	var session auth.Session
	if err := json.Unmarshal(data, &session); err != nil {
		slog.Error("redis session store: failed to unmarshal session", "error", err)
		return nil
	}

	return &session
}

// DeleteSession removes a session.
func (s *SessionStore) DeleteSession(sessionID string) {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID
	if err := s.client.Del(ctx, key).Err(); err != nil {
		slog.Error("redis session store: failed to delete session", "error", err)
	}
}

// UpdateSession updates an existing session's auth request.
func (s *SessionStore) UpdateSession(sessionID string, authRequest *protocol.AuthorizationRequestMessage) error {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	// GET existing session
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found")
		}
		return fmt.Errorf("redis get: %w", err)
	}

	var session auth.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	session.AuthRequest = authRequest

	newData, err := json.Marshal(&session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	// Preserve the remaining TTL
	ttl, err := s.client.TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		ttl = s.ttl
	}

	if err := s.client.Set(ctx, key, newData, ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}

	return nil
}

// CompleteSession marks a session as completed with tokens.
// Extends the TTL to 2 minutes so the frontend can poll for completion.
func (s *SessionStore) CompleteSession(sessionID, accessToken, refreshToken string) error {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found")
		}
		return fmt.Errorf("redis get: %w", err)
	}

	var session auth.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	session.Completed = true
	session.AccessToken = accessToken
	session.RefreshToken = refreshToken
	session.CompletedAt = time.Now()
	session.ExpiresAt = time.Now().Add(2 * time.Minute)

	newData, err := json.Marshal(&session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	// Set with the extended 2-minute TTL
	if err := s.client.Set(ctx, key, newData, 2*time.Minute).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}

	return nil
}

// ListSessions returns information about all active sessions.
// Uses SCAN to iterate over session keys without blocking.
func (s *SessionStore) ListSessions() []*auth.SessionInfo {
	ctx := context.Background()
	var sessions []*auth.SessionInfo

	iter := s.client.Scan(ctx, 0, sessionKeyPrefix+"*", defaultSessionScanCount).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var session auth.Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		info := &auth.SessionInfo{
			ID:        session.ID,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			Completed: session.Completed,
		}
		if session.Completed {
			info.CompletedAt = session.CompletedAt
		}
		sessions = append(sessions, info)
	}

	return sessions
}

// Count returns the current number of sessions.
// Uses SCAN to count keys matching the session prefix.
func (s *SessionStore) Count() int64 {
	ctx := context.Background()
	var count int64

	iter := s.client.Scan(ctx, 0, sessionKeyPrefix+"*", defaultSessionScanCount).Iterator()
	for iter.Next(ctx) {
		count++
	}
	return count
}

// Stop is a no-op for the Redis store. Redis handles TTL expiry natively,
// so there is no cleanup goroutine to stop.
func (s *SessionStore) Stop() {}
