package jwttoken

type JWTDetails struct {
	Token          string
	UserID         string
	Login          string
	IAT            int64
	EXP            int64
	RefreshTokenID string
	RoleID         string
}
