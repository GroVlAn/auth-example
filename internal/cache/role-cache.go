package gocache

import (
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
)

type RoleCache struct {
	cache    *GoCache
	cacheTTL time.Duration
}

func NewRoleCache(cache *GoCache, cacheTTL time.Duration) *RoleCache {
	return &RoleCache{
		cache:    cache,
		cacheTTL: cacheTTL,
	}
}

func (rc *RoleCache) SetPermissions(roleID string, permissions map[string]struct{}) {
	cacheKey := core.CachePrefixPermission.CreateCacheKey(roleID)
	rc.cache.Set(
		cacheKey,
		permissions,
		rc.cacheTTL,
	)
}

func (rc *RoleCache) GetPermissions(roleID string) (map[string]struct{}, bool) {
	cacheKey := core.CachePrefixPermission.CreateCacheKey(roleID)
	if perms, ok := rc.cache.Get(cacheKey); ok {
		return perms.(map[string]struct{}), true
	}

	return nil, false
}

func (rc *RoleCache) DeletePermissions(roleID string) {
	cacheKey := core.CachePrefixPermission.CreateCacheKey(roleID)

	rc.cache.Delete(
		cacheKey,
	)
}
