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

	// oauthCodeKeyPrefix is the Redis key prefix for the code->sessionID index.
	oauthCodeKeyPrefix = "pp:oauth:code:"

	// oauthSessionCountKey is the Redis key for the atomic OAuth session counter.
	oauthSessionCountKey = "pp:oauth:sess:_count"

	// oauthCodeTTL is how long authorization codes are valid.
	oauthCodeTTL = 5 * time.Minute
)

// reserveOAuthSessionScript atomically increments the OAuth session counter and
// checks whether the new value exceeds the capacity limit. If over limit, it
// decrements back and returns 0. Otherwise it returns 1, reserving a slot.
//
// KEYS[1] = counter key (pp:oauth:sess:_count)
// ARGV[1] = max sessions
//
// Returns 1 if a slot was reserved, 0 if at capacity.
var reserveOAuthSessionScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count > tonumber(ARGV[1]) then
	redis.call('DECR', KEYS[1])
	return 0
end
return 1
`)

// setCodeScript atomically sets the authorization code on an existing session.
// It GETs the session, decodes it, updates code/code_expires/user_did/kyc,
// writes it back with KEEPTTL, and creates the code index key — all in one
// atomic Lua script to eliminate the TOCTOU race in the original GET+SET flow.
//
// KEYS[1] = session key     (pp:oauth:sess:{id})
// KEYS[2] = code index key  (pp:oauth:code:{code})
// ARGV[1] = code
// ARGV[2] = code_expires    (RFC 3339 string, matching Go json.Marshal of time.Time)
// ARGV[3] = user_did
// ARGV[4] = kyc             ("true" / "false")
// ARGV[5] = code TTL        (seconds)
// ARGV[6] = session ID      (value stored in the code index key)
//
// Returns {1} on success, {0} if the session does not exist.
var setCodeScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return {0} end
local session = cjson.decode(data)
session.code = ARGV[1]
session.code_expires = ARGV[2]
session.user_did = ARGV[3]
session.kyc = (ARGV[4] == 'true')
redis.call('SET', KEYS[1], cjson.encode(session), 'KEEPTTL')
redis.call('SET', KEYS[2], ARGV[6], 'EX', tonumber(ARGV[5]))
return {1}
`)

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
// It maintains a dual index: session ID -> session data, and authorization code -> session ID.
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
// Uses an atomic Lua script to reserve a slot in the counter, preventing
// race conditions across multiple proxy instances.
func (s *OAuthSessionStore) CreateSession(clientID, redirectURI, state, authSessionID string) string {
	ctx := context.Background()

	// Atomically reserve a session slot via the counter.
	if s.maxSessions > 0 {
		reserved, err := reserveOAuthSessionScript.Run(ctx, s.client, []string{oauthSessionCountKey}, s.maxSessions).Int()
		if err != nil {
			slog.Error("redis oauth store: failed to reserve session slot", "error", err)
			return ""
		}
		if reserved == 0 {
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
		// Release the reserved slot since we failed to create the session.
		if s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return ""
	}

	key := oauthSessionKeyPrefix + sessionID
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		slog.Error("redis oauth store: failed to store session", "error", err)
		// Release the reserved slot since we failed to store the session.
		if s.maxSessions > 0 {
			s.decrCount(ctx)
		}
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

// SetCode atomically sets the authorization code for a session.
// Uses a Lua script to eliminate the TOCTOU race between reading and updating the session.
func (s *OAuthSessionStore) SetCode(sessionID, code, userDID string, kyc bool) error {
	ctx := context.Background()
	sessKey := oauthSessionKeyPrefix + sessionID
	codeKey := oauthCodeKeyPrefix + code

	codeExpires := time.Now().Add(oauthCodeTTL)
	codeTTLSeconds := int64(oauthCodeTTL.Seconds())

	kycStr := "false"
	if kyc {
		kycStr = "true"
	}

	result, err := setCodeScript.Run(ctx, s.client,
		[]string{sessKey, codeKey},
		code,
		codeExpires.Format(time.RFC3339Nano),
		userDID,
		kycStr,
		codeTTLSeconds,
		sessionID,
	).Slice()
	if err != nil {
		return fmt.Errorf("redis setCode script: %w", err)
	}

	if len(result) < 1 {
		return fmt.Errorf("session not found")
	}

	success, ok := result[0].(int64)
	if !ok || success != 1 {
		return fmt.Errorf("session not found")
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

// DeleteSession removes an OAuth session, its code index entry, and decrements
// the atomic session counter.
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
		deleted, delErr := s.client.Del(ctx, sessKey).Result()
		if delErr != nil {
			slog.Error("redis oauth store: failed to delete session key", "error", delErr)
		}
		if deleted > 0 && s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return
	}

	var session types.OAuthSession
	keys := []string{sessKey}
	if err := json.Unmarshal(data, &session); err == nil && session.Code != "" {
		keys = append(keys, oauthCodeKeyPrefix+session.Code)
	}

	deleted, err := s.client.Del(ctx, keys...).Result()
	if err != nil {
		slog.Error("redis oauth store: failed to delete session", "error", err)
		return
	}

	// The session key is always first in the keys slice. If at least one key
	// was deleted and we know the session key existed (we read it above),
	// decrement the counter.
	if deleted > 0 && s.maxSessions > 0 {
		s.decrCount(ctx)
	}
}

// Stop is a no-op for the Redis store. Redis handles TTL expiry natively.
func (s *OAuthSessionStore) Stop() {}

// decrCount decrements the OAuth session counter, clamping at zero to prevent
// negative drift from TTL-expired sessions that were never explicitly deleted.
func (s *OAuthSessionStore) decrCount(ctx context.Context) {
	val, err := s.client.Decr(ctx, oauthSessionCountKey).Result()
	if err != nil {
		slog.Error("redis oauth store: failed to decrement session count", "error", err)
		return
	}
	// If the counter went negative (e.g. Redis restart lost the counter but
	// sessions expired naturally), reset it to zero.
	if val < 0 {
		s.client.Set(ctx, oauthSessionCountKey, 0, 0)
	}
}

// generateSecureCode generates a cryptographically secure random hex string.
func generateSecureCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
