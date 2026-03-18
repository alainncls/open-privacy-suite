package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// RateLimiter implements server.RateLimiterInterface using Redis for distributed
// rate limiting. It uses a Lua script to atomically check and increment both
// a sliding-window RPS counter (sorted set) and a daily counter (string key).
type RateLimiter struct {
	client *goredis.Client
}

// NewRateLimiter creates a Redis-backed rate limiter.
func NewRateLimiter(client *goredis.Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// checkAndIncrScript atomically checks RPS + daily limits and increments counters
// if both checks pass. Returns {1, ""} on success or {0, reason} on denial.
//
// KEYS[1] = rps sorted set key
// KEYS[2] = daily counter key
// ARGV[1] = now in microseconds (score for sorted set)
// ARGV[2] = window start in microseconds (cutoff for old entries)
// ARGV[3] = rps limit (0 = unlimited)
// ARGV[4] = daily limit (0 = unlimited)
// ARGV[5] = unique member ID for the sorted set entry
var checkAndIncrScript = goredis.NewScript(`
local rps_key = KEYS[1]
local daily_key = KEYS[2]
local now_us = tonumber(ARGV[1])
local window_start_us = tonumber(ARGV[2])
local rps_limit = tonumber(ARGV[3])
local daily_limit = tonumber(ARGV[4])
local member_id = ARGV[5]

-- Clean old RPS entries outside the sliding window
redis.call('ZREMRANGEBYSCORE', rps_key, '-inf', window_start_us)

-- Check RPS limit
if rps_limit > 0 then
    local rps_count = redis.call('ZCARD', rps_key)
    if rps_count >= rps_limit then
        return {0, 'rate limit exceeded (requests per second)'}
    end
end

-- Check daily limit
if daily_limit > 0 then
    local daily_count = tonumber(redis.call('GET', daily_key) or '0')
    if daily_count >= daily_limit then
        return {0, 'rate limit exceeded (daily limit)'}
    end
end

-- All checks passed — increment both counters
redis.call('ZADD', rps_key, now_us, member_id)
redis.call('EXPIRE', rps_key, 2)
redis.call('INCR', daily_key)
-- Daily key TTL: 48 hours to survive past midnight regardless of timezone
redis.call('EXPIRE', daily_key, 172800)
return {1, ''}
`)

// CheckAndIncrement checks if a request is allowed under both RPS and daily
// limits, and atomically increments the counters if allowed. On Redis errors,
// it fails open (allows the request) to avoid blocking traffic during outages.
func (r *RateLimiter) CheckAndIncrement(userID string, rpsLimit, dailyLimit *int) (bool, string) {
	now := time.Now().UTC()
	nowUs := now.UnixMicro()
	windowStartUs := now.Add(-time.Second).UnixMicro()

	rpsLimitVal := 0
	if rpsLimit != nil {
		rpsLimitVal = *rpsLimit
	}
	dailyLimitVal := 0
	if dailyLimit != nil {
		dailyLimitVal = *dailyLimit
	}

	rpsKey := fmt.Sprintf("pp:rl:rps:%s", userID)
	dailyKey := fmt.Sprintf("pp:rl:daily:%s:%s", userID, now.Format("20060102"))
	// Unique member: microsecond timestamp + random suffix to avoid collisions
	// across concurrent goroutines within the same microsecond.
	var randBuf [8]byte
	_, _ = rand.Read(randBuf[:])
	memberID := fmt.Sprintf("%d:%s", nowUs, hex.EncodeToString(randBuf[:]))

	ctx := context.Background()
	result, err := checkAndIncrScript.Run(ctx, r.client,
		[]string{rpsKey, dailyKey},
		nowUs, windowStartUs, rpsLimitVal, dailyLimitVal, memberID,
	).Slice()

	if err != nil {
		// Fail open: allow the request if Redis is unavailable
		slog.Warn("redis rate limiter error, failing open", "error", err, "user_id", userID)
		return true, ""
	}

	allowed, _ := result[0].(int64)
	reason, _ := result[1].(string)
	return allowed == 1, reason
}

// Stop is a no-op for the Redis rate limiter — there is no background goroutine.
// Redis handles TTL-based cleanup automatically.
func (r *RateLimiter) Stop() {}
