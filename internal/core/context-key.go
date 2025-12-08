package core

type ContextKey string

const (
	RefreshTokenKey ContextKey = "refresh_token"
	AccessTokenKey  ContextKey = "access_token"
)
