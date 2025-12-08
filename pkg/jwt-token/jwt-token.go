package jwttoken

import (
	"fmt"

	"github.com/golang-jwt/jwt"
)

func ParseToken(secretKey string, token string) (JWTDetails, error) {
	tokenClaims := jwt.MapClaims{}

	jwtToken, err := jwt.ParseWithClaims(
		token,
		tokenClaims,
		func(token *jwt.Token) (interface{}, error) {

			switch token.Method.Alg() {
			case jwt.SigningMethodHS256.Alg():
				return []byte(secretKey), nil
			default:
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		},
	)
	if err != nil {
		return JWTDetails{}, fmt.Errorf("parsing access token: %w", err)
	}

	tokenDetails, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return JWTDetails{}, ErrInvalidToken
	}

	return JWTDetails{
		Token:          token,
		UserID:         tokenDetails["user_id"].(string),
		Login:          tokenDetails["login"].(string),
		IAT:            tokenDetails["iat"].(int64),
		EXP:            tokenDetails["exp"].(int64),
		RefreshTokenID: tokenDetails["refresh_token_id"].(string),
	}, nil
}
