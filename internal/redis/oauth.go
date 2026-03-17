package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"privacy-proxy/internal/types"

	"github.com/redis/go-redis/v9"
)

const (
	// oauthSessionKeyPrefix is the Redis key prefix for OAuth sessions.
	oauthSessionKeyPrefix = "pp:oauth:sess:"

	// oauthCodeKeyPrefix is the Redis key prefix for the code→sessionID index.
	oauthCodeKeyPrefix = "pp:oauth:code:"

	// oauthCodeTTL is how long authorization codes are valid.
	oauthCodeTTL = 5 * time.Minute
)

// markCodeUsedScript atomically marks an OAuth authorization code as used.
// It looks up the session via the code index, checks that the code hasn't been
// used yet, sets code_used=true, persists the session, and deletes the code index
// entry — all in a single atomic Lua script to prevent replay attacks.
//
// KEYS[1] = code index key (pp:oauth:code:{code})
// ARGV[1] = session key prefix (pp:oauth:sess:)
//
// Returns {1, sessionID} on success, {0, ""} on failure.
var markCodeUsedScript = redis.NewScript(`
local sess_id = redis.call('GET', KEYS[1])
if not sess_id then return {0, ''} end
local sess_key = ARGV[1] .. sess_id
local data = redis.call('GET', sess_key)
if not data then return {0, ''} end
local session = cjson.decode(data)
if session.code_used then return {0, ''} end
session.code_used = true
redis.call('SET', sess_key, cjson.encode(session), 'KEEPTTL')
redis.call('DEL', KEYS[1])
return {1, sess_id}
`)

// OAuthSessionStore is a Redis-backed implementation of the OAuthSessionManager interface.
// It maintains a dual index: session ID → session data, and authorization code → session ID.
type OAuthSessionStore struct {
	client      *redis.Client
	ttl         time.Duration
	maxSessions int
}

// NewOAuthSessionStore creates a new Redis-backed OAuth session store.
func NewOAuthSessionStore(client *redis.Client, sessionTTL time.Duration, maxSessions int) *OAuthSessionStore {
	return &OAuthSessionStore{
		client:      client,
		ttl:         sessionTTL,
		maxSessions: maxSessions,
	}
}

// CreateSession creates a new OAuth session.
// Returns the session ID or empty string if at capacity.
func (s *OAuthSessionStore) CreateSession(clientID, redirectURI, state, authSessionID string) string {
	ctx := context.Background()

	// Approximate capacity check via SCAN.
	if s.maxSessions > 0 {
		count := s.countSessions(ctx)
		if count >= int64(s.maxSessions) {
			return ""
		}
	}

	sessionID := generateSecureCode()
	now := time.Now()

	session := &types.OAuthSession{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		AuthSessionID: authSessionID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.ttl),
	}

	data, err := json.Marshal(session)
	if err != nil {
		slog.Error("redis oauth store: failed to marshal session", "error", err)
		return ""
	}

	key := oauthSessionKeyPrefix + sessionID
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		slog.Error("redis oauth store: failed to store session", "error", err)
		return ""
	}

	return sessionID
}

// GetSession retrieves an OAuth session by ID.
func (s *OAuthSessionStore) GetSession(sessionID string) *types.OAuthSession {
	ctx := context.Background()
	key := oauthSessionKeyPrefix + sessionID

	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis oauth store: failed to get session", "error", err)
		}
		return nil
	}

	var session types.OAuthSession
	if err := json.Unmarshal(data, &session); err != nil {
		slog.Error("redis oauth store: failed to unmarshal session", "error", err)
		return nil
	}

	return &session
}

// GetSessionByCode retrieves an OAuth session by authorization code.
func (s *OAuthSessionStore) GetSessionByCode(code string) *types.OAuthSession {
	ctx := context.Background()
	codeKey := oauthCodeKeyPrefix + code

	sessionID, err := s.client.Get(ctx, codeKey).Result()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis oauth store: failed to get code index", "error", err)
		}
		return nil
	}

	return s.GetSession(sessionID)
}

// SetCode sets the authorization code for a session.
func (s *OAuthSessionStore) SetCode(sessionID, code, userDID string, kyc bool) error {
	ctx := context.Background()
	sessKey := oauthSessionKeyPrefix + sessionID

	// Get and update the session
	data, err := s.client.Get(ctx, sessKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found")
		}
		return fmt.Errorf("redis get: %w", err)
	}

	var session types.OAuthSession
	if err := json.Unmarshal(data, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	session.Code = code
	session.CodeExpires = time.Now().Add(oauthCodeTTL)
	session.UserDID = userDID
	session.KYC = kyc

	newData, err := json.Marshal(&session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	// Preserve the remaining TTL on the session key
	ttl, err := s.client.TTL(ctx, sessKey).Result()
	if err != nil || ttl <= 0 {
		ttl = s.ttl
	}

	// Pipeline: update session + create code index
	pipe := s.client.Pipeline()
	pipe.Set(ctx, sessKey, newData, ttl)

	// Code index TTL = min(code TTL, session remaining TTL) so the index
	// never outlives the session.
	codeTTL := oauthCodeTTL
	if ttl < codeTTL {
		codeTTL = ttl
	}
	codeKey := oauthCodeKeyPrefix + code
	pipe.Set(ctx, codeKey, sessionID, codeTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis pipeline: %w", err)
	}

	return nil
}

// MarkCodeUsed atomically marks the authorization code as used (single-use).
// Returns true if the code was valid and successfully marked, false otherwise.
// Uses a Lua script to prevent replay attacks via race conditions.
func (s *OAuthSessionStore) MarkCodeUsed(code string) bool {
	ctx := context.Background()
	codeKey := oauthCodeKeyPrefix + code

	result, err := markCodeUsedScript.Run(ctx, s.client, []string{codeKey}, oauthSessionKeyPrefix).Slice()
	if err != nil {
		slog.Error("redis oauth store: markCodeUsed script failed", "error", err)
		return false
	}

	if len(result) < 1 {
		return false
	}

	// The Lua script returns {1, sessionID} on success.
	success, ok := result[0].(int64)
	if !ok {
		return false
	}

	return success == 1
}

// DeleteSession removes an OAuth session and its code index entry.
func (s *OAuthSessionStore) DeleteSession(sessionID string) {
	ctx := context.Background()
	sessKey := oauthSessionKeyPrefix + sessionID

	// Read session first to find the code for index cleanup.
	data, err := s.client.Get(ctx, sessKey).Bytes()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis oauth store: failed to get session for deletion", "error", err)
		}
		// Even if we can't read the session, try to delete the key.
		s.client.Del(ctx, sessKey)
		return
	}

	var session types.OAuthSession
	keys := []string{sessKey}
	if err := json.Unmarshal(data, &session); err == nil && session.Code != "" {
		keys = append(keys, oauthCodeKeyPrefix+session.Code)
	}

	if err := s.client.Del(ctx, keys...).Err(); err != nil {
		slog.Error("redis oauth store: failed to delete session", "error", err)
	}
}

// Stop is a no-op for the Redis store. Redis handles TTL expiry natively.
func (s *OAuthSessionStore) Stop() {}

// countSessions counts OAuth session keys via SCAN.
func (s *OAuthSessionStore) countSessions(ctx context.Context) int64 {
	var count int64
	iter := s.client.Scan(ctx, 0, oauthSessionKeyPrefix+"*", defaultSessionScanCount).Iterator()
	for iter.Next(ctx) {
		count++
	}
	return count
}

// generateSecureCode generates a cryptographically secure random hex string.
func generateSecureCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
