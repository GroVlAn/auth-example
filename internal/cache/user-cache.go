package gocache

import (
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
)

type UserCache struct {
	cache    *GoCache
	cacheTTL time.Duration
}

func NewUserCache(cache *GoCache, cacheTTL time.Duration) *UserCache {
	return &UserCache{
		cache:    cache,
		cacheTTL: cacheTTL,
	}
}

func (uc *UserCache) SetUser(user core.User) {
	uc.cache.Set(
		core.CachePrefixUserByID.CreateCacheKey(user.ID),
		user,
		uc.cacheTTL,
	)

	uc.cache.Set(
		core.CachePrefixUserByUsername.CreateCacheKey(user.Username),
		user.ID,
		uc.cacheTTL,
	)

	uc.cache.Set(
		core.CachePrefixUserByEmail.CreateCacheKey(user.Email),
		user.ID,
		uc.cacheTTL,
	)
}

func (uc *UserCache) GetUserByID(id string) (core.User, bool) {
	cacheKey := core.CachePrefixUserByID.CreateCacheKey(id)

	if user, ok := uc.cache.Get(cacheKey); ok {
		return user.(core.User), true
	}

	return core.User{}, false
}

func (uc *UserCache) GetUserByUsername(username string) (core.User, bool) {
	cacheKey := core.CachePrefixUserByUsername.CreateCacheKey(username)

	if id, ok := uc.cache.Get(cacheKey); ok {
		return uc.GetUserByID(id.(string))
	}

	return core.User{}, false
}

func (uc *UserCache) GetUserByEmail(email string) (core.User, bool) {
	cacheKey := core.CachePrefixUserByEmail.CreateCacheKey(email)

	if id, ok := uc.cache.Get(cacheKey); ok {
		return uc.GetUserByID(id.(string))
	}

	return core.User{}, false
}

func (uc *UserCache) DeleteUser(user core.User) {
	idCacheKey := core.CachePrefixUserByID.CreateCacheKey(user.ID)
	usernameCacheKey := core.CachePrefixUserByUsername.CreateCacheKey(user.Username)
	emailCacheKey := core.CachePrefixUserByEmail.CreateCacheKey(user.Email)

	uc.cache.Delete(idCacheKey)
	uc.cache.Delete(usernameCacheKey)
	uc.cache.Delete(emailCacheKey)
}

func (uc *UserCache) ClearUsers() {
	uc.cache.DeleteByPrefix(string(core.CachePrefixUserByID))
	uc.cache.DeleteByPrefix(string(core.CachePrefixUserByUsername))
	uc.cache.DeleteByPrefix(string(core.CachePrefixUserByEmail))
}
