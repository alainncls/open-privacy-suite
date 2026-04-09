package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Client is an alias for the go-redis Client type.
type Client = redis.Client

// NewClient creates a shared Redis client from a URL.
// The URL must include a password — unprotected Redis is rejected.
func NewClient(redisURL string) (*Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("REDIS_URL must include a password (e.g., redis://:password@host:6379/0)")
	}
	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}
	return client, nil
}
