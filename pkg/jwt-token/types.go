package jwttoken

type JWTDetails struct {
	UserID         string
	Login          string
	IAT            int64
	EXP            int64
	RefreshTokenID string
}
