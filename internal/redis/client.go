package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Client is an alias for the go-redis Client type, re-exported so that
// callers can reference the type through this package without importing
// github.com/redis/go-redis/v9 directly.
type Client = redis.Client

// NewClient creates a shared Redis client from a URL (e.g., "redis://localhost:6379").
func NewClient(redisURL string) (*Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}
	return client, nil
}
