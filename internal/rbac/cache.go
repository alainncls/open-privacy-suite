package rbac

import (
	"sync"
	"time"
)

// Cache provides an in-memory cache for effective permissions.
// It uses a TTL-based expiration with LRU eviction when at capacity.
type Cache struct {
	mu          sync.RWMutex
	wg          sync.WaitGroup
	entries     map[string]*cacheEntry
	ttl         time.Duration
	maxEntries  int
	accessOrder []string // For LRU eviction
	stopCh      chan struct{}
}

type cacheEntry struct {
	permissions *EffectivePermissions
	expiresAt   time.Time
}

// CacheConfig holds configuration for the permission cache.
type CacheConfig struct {
	TTL        time.Duration // Default TTL for cache entries (default: 5 minutes)
	MaxEntries int           // Maximum number of entries (default: 10000)
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 10000,
	}
}

// NewCache creates a new permission cache.
func NewCache(config CacheConfig) *Cache {
	if config.TTL == 0 {
		config.TTL = 5 * time.Minute
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = 10000
	}

	c := &Cache{
		entries:     make(map[string]*cacheEntry),
		ttl:         config.TTL,
		maxEntries:  config.MaxEntries,
		accessOrder: make([]string, 0),
		stopCh:      make(chan struct{}),
	}

	// Start background cleanup goroutine
	c.wg.Add(1)
	go c.cleanupLoop()

	return c
}

// cacheKey creates a unique key for a user+org combination.
func cacheKey(userID, orgID string) string {
	return userID + ":" + orgID
}

// Get retrieves cached permissions for a user in an organization.
// Returns nil if not found or expired.
func (c *Cache) Get(userID, orgID string) *EffectivePermissions {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(userID, orgID)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	// Update access order for LRU tracking
	c.updateAccessOrder(key)

	return entry.permissions
}

// Set stores permissions in the cache.
func (c *Cache) Set(perms *EffectivePermissions) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(perms.UserID, perms.OrgID)

	// Check if we need to evict entries
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		c.evictLRU()
	}

	c.entries[key] = &cacheEntry{
		permissions: perms,
		expiresAt:   time.Now().Add(c.ttl),
	}

	// Update access order for LRU
	c.updateAccessOrder(key)
}

// SetWithTTL stores permissions with a custom TTL.
func (c *Cache) SetWithTTL(perms *EffectivePermissions, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(perms.UserID, perms.OrgID)

	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		c.evictLRU()
	}

	c.entries[key] = &cacheEntry{
		permissions: perms,
		expiresAt:   time.Now().Add(ttl),
	}

	c.updateAccessOrder(key)
}

// InvalidateUser removes all cached permissions for a user.
func (c *Cache) InvalidateUser(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find and delete all entries for this user
	for key := range c.entries {
		if len(key) > len(userID) && key[:len(userID)] == userID && key[len(userID)] == ':' {
			delete(c.entries, key)
			c.removeFromAccessOrder(key)
		}
	}
}

// InvalidateOrg removes all cached permissions for an organization.
func (c *Cache) InvalidateOrg(orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	suffix := ":" + orgID
	for key := range c.entries {
		if len(key) > len(suffix) && key[len(key)-len(suffix):] == suffix {
			delete(c.entries, key)
			c.removeFromAccessOrder(key)
		}
	}
}

// Invalidate removes a specific user+org entry from the cache.
func (c *Cache) Invalidate(userID, orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(userID, orgID)
	delete(c.entries, key)
	c.removeFromAccessOrder(key)
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
	c.accessOrder = make([]string, 0)
}

// Size returns the current number of entries in the cache.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// HitRate returns cache statistics (hits/total since last reset).
// Note: This is a simple implementation; production may want more detailed metrics.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var expired int
	now := time.Now()
	for _, entry := range c.entries {
		if now.After(entry.expiresAt) {
			expired++
		}
	}

	return CacheStats{
		Entries:        len(c.entries),
		ExpiredPending: expired,
		MaxEntries:     c.maxEntries,
	}
}

// CacheStats contains cache statistics.
type CacheStats struct {
	Entries        int `json:"entries"`
	ExpiredPending int `json:"expired_pending"`
	MaxEntries     int `json:"max_entries"`
}

// evictLRU removes the least recently used entry.
// Must be called with lock held.
func (c *Cache) evictLRU() {
	if len(c.accessOrder) == 0 {
		return
	}

	// Remove the oldest entry
	key := c.accessOrder[0]
	c.accessOrder = c.accessOrder[1:]
	delete(c.entries, key)
}

// updateAccessOrder moves a key to the end of the access order list.
// Must be called with lock held.
func (c *Cache) updateAccessOrder(key string) {
	// Remove existing entry if present
	c.removeFromAccessOrder(key)

	// Add to end
	c.accessOrder = append(c.accessOrder, key)
}

// removeFromAccessOrder removes a key from the access order list.
// Must be called with lock held.
func (c *Cache) removeFromAccessOrder(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			return
		}
	}
}

// cleanupLoop periodically removes expired entries.
func (c *Cache) cleanupLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (c *Cache) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

// cleanup removes expired entries from the cache.
func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			c.removeFromAccessOrder(key)
		}
	}
}
