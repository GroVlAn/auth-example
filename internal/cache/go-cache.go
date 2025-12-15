package gocache

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

type GoCache struct {
	c *cache.Cache
}

func New(defaultExpiration, cleanupInterval time.Duration) *GoCache {
	return &GoCache{
		c: cache.New(
			defaultExpiration,
			cleanupInterval,
		),
	}
}

func (gc *GoCache) Get(key string) (any, bool) {
	return gc.c.Get(key)
}

func (gc *GoCache) Set(key string, value any, ttl time.Duration) {
	gc.c.Set(key, value, ttl)
}

func (gc *GoCache) Delete(key string) {
	gc.c.Delete(key)
}

func (gc *GoCache) DeleteByPrefix(prefix string) {
	for k := range gc.c.Items() {
		if strings.HasPrefix(k, prefix) {
			gc.c.Delete(k)
		}
	}
}
