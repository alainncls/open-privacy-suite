package rbac

import "time"

// PermissionCache abstracts permission caching for horizontal scaling.
type PermissionCache interface {
	Get(userID, orgID string) *EffectivePermissions
	Set(perms *EffectivePermissions)
	SetWithTTL(perms *EffectivePermissions, ttl time.Duration)
	InvalidateUser(userID string)
	InvalidateOrg(orgID string)
	Invalidate(userID, orgID string)
	Clear()
	Size() int
	Stats() CacheStats
	Stop()
}

// Verify that the concrete type implements the interface.
var _ PermissionCache = (*Cache)(nil)
