package rbac

import (
	"testing"
	"time"
)

func TestCacheBasicOperations(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	perms := &EffectivePermissions{
		UserID:         "user1",
		OrgID:          "org1",
		AllowedMethods: []string{"eth_call"},
		DefaultClaims:  []Claim{ClaimRead},
	}

	// Test Set and Get
	cache.Set(perms)

	got := cache.Get("user1", "org1")
	if got == nil {
		t.Fatal("Expected to get cached permissions")
	}
	if len(got.AllowedMethods) != 1 || got.AllowedMethods[0] != "eth_call" {
		t.Errorf("Got unexpected permissions: %v", got)
	}

	// Test Get for non-existent entry
	got = cache.Get("user2", "org1")
	if got != nil {
		t.Error("Expected nil for non-existent entry")
	}
}

func TestCacheExpiration(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        50 * time.Millisecond,
		MaxEntries: 100,
	})

	perms := &EffectivePermissions{
		UserID:         "user1",
		OrgID:          "org1",
		AllowedMethods: []string{"eth_call"},
	}

	cache.Set(perms)

	// Should exist immediately
	got := cache.Get("user1", "org1")
	if got == nil {
		t.Fatal("Expected to get cached permissions immediately")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired now
	got = cache.Get("user1", "org1")
	if got != nil {
		t.Error("Expected nil for expired entry")
	}
}

func TestCacheInvalidateUser(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	// Add entries for same user in different orgs
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org2"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})

	// Invalidate user1
	cache.InvalidateUser("user1")

	// user1 entries should be gone
	if cache.Get("user1", "org1") != nil {
		t.Error("Expected user1:org1 to be invalidated")
	}
	if cache.Get("user1", "org2") != nil {
		t.Error("Expected user1:org2 to be invalidated")
	}

	// user2 should still exist
	if cache.Get("user2", "org1") == nil {
		t.Error("Expected user2:org1 to still exist")
	}
}

func TestCacheInvalidateOrg(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	// Add entries for different users in same org
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org2"})

	// Invalidate org1
	cache.InvalidateOrg("org1")

	// org1 entries should be gone
	if cache.Get("user1", "org1") != nil {
		t.Error("Expected user1:org1 to be invalidated")
	}
	if cache.Get("user2", "org1") != nil {
		t.Error("Expected user2:org1 to be invalidated")
	}

	// org2 should still exist
	if cache.Get("user1", "org2") == nil {
		t.Error("Expected user1:org2 to still exist")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 3,
	})

	// Add 3 entries
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user3", OrgID: "org1"})

	// Access user1 to make it recently used
	_ = cache.Get("user1", "org1")

	// Add 4th entry - should evict user2 (least recently used)
	cache.Set(&EffectivePermissions{UserID: "user4", OrgID: "org1"})

	// user1 should still exist (accessed recently)
	if cache.Get("user1", "org1") == nil {
		t.Error("Expected user1:org1 to still exist (recently accessed)")
	}

	// user3 should still exist (added after user2)
	if cache.Get("user3", "org1") == nil {
		t.Error("Expected user3:org1 to still exist")
	}

	// user4 should exist
	if cache.Get("user4", "org1") == nil {
		t.Error("Expected user4:org1 to exist")
	}

	// Check size
	if cache.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cache.Size())
	}
}

func TestCacheClear(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})

	if cache.Size() != 2 {
		t.Errorf("Expected size 2 before clear, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}
}

func TestCacheStats(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})

	stats := cache.Stats()

	if stats.Entries != 2 {
		t.Errorf("Expected 2 entries, got %d", stats.Entries)
	}
	if stats.MaxEntries != 100 {
		t.Errorf("Expected max entries 100, got %d", stats.MaxEntries)
	}
}

func TestCacheSetWithCustomTTL(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	perms := &EffectivePermissions{
		UserID: "user1",
		OrgID:  "org1",
	}

	// Set with short TTL
	cache.SetWithTTL(perms, 50*time.Millisecond)

	// Should exist immediately
	if cache.Get("user1", "org1") == nil {
		t.Fatal("Expected entry to exist immediately")
	}

	// Wait for custom TTL expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cache.Get("user1", "org1") != nil {
		t.Error("Expected entry to be expired after custom TTL")
	}
}
