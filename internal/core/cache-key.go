package core

type CachePrefix string

const (
	CachePrefixRefreshToken   CachePrefix = "token:refresh"
	CachePrefixAccessToken    CachePrefix = "token:access"
	CachePrefixUserByID       CachePrefix = "user:id"
	CachePrefixUserByUsername CachePrefix = "user:username"
	CachePrefixUserByEmail    CachePrefix = "user:email"
	CachePrefixPermission     CachePrefix = "permission"
)

func (cp CachePrefix) CreateCacheKey(identifiers string) string {
	return string(cp) + ":" + identifiers
}
