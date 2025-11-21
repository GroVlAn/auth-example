package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type DepsAuthService struct {
	TokenRefreshEndTTL time.Duration
	TokenAccessEndTTL  time.Duration
	SecretKey          string
}

type authRepo interface {
	CreateTokens(ctx context.Context, accToken core.AccessToken, rfToken core.RefreshToken, artID string) error
	CreateAccessToken(ctx context.Context, token core.AccessToken) error
	AccessToken(ctx context.Context, token string) (core.AccessToken, error)
	DeleteAccessToken(ctx context.Context, token string) error
	DeleteAllAccessTokens(ctx context.Context, userID string) error
	RefreshToken(ctx context.Context, token string) (core.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, userID string) error
}

type authService struct {
	userRepo userRepo
	authRepo authRepo
	DepsAuthService
}

func NewAuthService(authRepo authRepo, userRepo userRepo, deps DepsAuthService) *authService {
	return &authService{
		authRepo:        authRepo,
		userRepo:        userRepo,
		DepsAuthService: deps,
	}
}

func (as *authService) Authenticate(ctx context.Context, authUser core.AuthUser) (core.RefreshToken, core.AccessToken, error) {
	user, err := as.user(ctx, authUser)
	if err != nil {
		return core.RefreshToken{}, core.AccessToken{}, fmt.Errorf("getting exist user: %w", err)
	}

	if err := as.verifyPassword(authUser.Password, user.PasswordHash); err != nil {
		return core.RefreshToken{}, core.AccessToken{}, fmt.Errorf("verifying password: %w", err)
	}

	refreshToken, err := as.createRefreshToken(user)
	if err != nil {
		return core.RefreshToken{}, core.AccessToken{}, fmt.Errorf("creating refresh token: %w", err)
	}

	accessToken, err := as.createAccessToken(refreshToken.ID, user)
	if err != nil {
		return core.RefreshToken{}, core.AccessToken{}, fmt.Errorf("creating access token: %w", err)
	}

	artID := uuid.NewString()

	if err := as.authRepo.CreateTokens(ctx, accessToken, refreshToken, artID); err != nil {
		return core.RefreshToken{}, core.AccessToken{}, fmt.Errorf("saving tokens: %w", err)
	}

	return refreshToken, accessToken, nil
}

func (as *authService) UpdateAccessToken(ctx context.Context, rfToken string) (core.AccessToken, error) {
	existRfToken, err := as.checkExistRefreshToken(ctx, rfToken)
	if err != nil {
		return core.AccessToken{}, e.NewErrUnauthorized(
			fmt.Errorf("checking exist refresh token: %w", err),
			"invalid token",
		)
	}

	tokenDetails, err := jwttoken.ParseToken(as.SecretKey, rfToken)
	if err != nil {
		return core.AccessToken{}, err
	}

	if err := as.checkExpiredRefreshToken(ctx, rfToken, tokenDetails); err != nil {
		return core.AccessToken{}, err
	}

	newToken, err := as.createAccessToken(existRfToken.ID,
		core.User{
			ID:       tokenDetails.UserID,
			Username: tokenDetails.Login,
		})
	if err != nil {
		return core.AccessToken{}, fmt.Errorf("creating access token: %w", err)
	}

	if err := as.authRepo.CreateAccessToken(ctx, newToken); err != nil {
		return core.AccessToken{}, fmt.Errorf("saving refresh token: %w", err)
	}

	return newToken, nil
}

func (as *authService) VerifyAccessToken(ctx context.Context, accToken string) error {
	if err := as.checkExistAccessToken(ctx, accToken); err != nil {
		return e.NewErrUnauthorized(
			fmt.Errorf("cheking access token: %w", err),
			"invalid token",
		)
	}

	tokenDetails, err := jwttoken.ParseToken(as.SecretKey, accToken)
	if err != nil {
		return err
	}

	if err := as.checkExpiredAccessToken(ctx, accToken, tokenDetails); err != nil {
		return err
	}

	return nil
}

func (as *authService) Logout(ctx context.Context, refreshToken, accessToken string) error {
	if err := as.authRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}

	if err := as.authRepo.DeleteAccessToken(ctx, accessToken); err != nil {
		return fmt.Errorf("deleting access token: %w", err)
	}

	return nil
}

func (as *authService) LogoutAllDevices(ctx context.Context, accToken string) error {
	tokenDetails, err := jwttoken.ParseToken(as.SecretKey, accToken)
	if err != nil {
		return e.NewErrUnauthorized(err, "invalid access token")
	}

	if err := as.authRepo.DeleteAllAccessTokens(ctx, tokenDetails.UserID); err != nil {
		return fmt.Errorf("deleting all access tokens: %w", err)
	}

	if err := as.authRepo.DeleteAllRefreshTokens(ctx, tokenDetails.UserID); err != nil {
		return fmt.Errorf("deleting all refresh tokens: %w", err)
	}

	return nil
}

func (as *authService) user(ctx context.Context, authUser core.AuthUser) (core.User, error) {
	switch {
	case authUser.Username != "":
		return as.userRepo.GetByUsername(ctx, authUser.Username)
	default:
		return as.userRepo.GetByEmail(ctx, authUser.Email)
	}
}

func (as *authService) createRefreshToken(user core.User) (core.RefreshToken, error) {
	refreshToken := core.RefreshToken{}
	refreshToken.StartTTL = time.Now()
	refreshToken.EndTTL = refreshToken.StartTTL.Add(as.TokenRefreshEndTTL)

	payload := jwt.MapClaims{
		"user_id": user.ID,
		"login":   user.Username,
		"iat":     refreshToken.StartTTL.Unix(),
		"exp":     refreshToken.EndTTL.Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	t, err := jwtToken.SignedString([]byte(as.SecretKey))
	if err != nil {
		return core.RefreshToken{}, e.NewErrInternal(fmt.Errorf("creating access token: %w", err))
	}

	refreshToken.ID = uuid.NewString()
	refreshToken.Token = t
	refreshToken.UserID = user.ID

	return refreshToken, nil
}

func (as *authService) createAccessToken(rfID string, user core.User) (core.AccessToken, error) {
	accessToken := core.AccessToken{}
	accessToken.StartTTL = time.Now()
	accessToken.EndTTL = accessToken.StartTTL.Add(as.TokenAccessEndTTL)

	payload := jwt.MapClaims{
		"refresh_token_id": rfID,
		"user_id":          user.ID,
		"login":            user.Username,
		"iat":              accessToken.StartTTL.Unix(),
		"exp":              accessToken.EndTTL.Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	t, err := jwtToken.SignedString([]byte(as.SecretKey))
	if err != nil {
		return core.AccessToken{}, e.NewErrInternal(fmt.Errorf("creating access token: %w", err))
	}

	accessToken.ID = uuid.NewString()
	accessToken.Token = t
	accessToken.UserID = user.ID

	return accessToken, nil
}

func (as *authService) verifyPassword(password, passwordHash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return e.NewErrUnauthorized(
			fmt.Errorf("comparing hash adn password: %w", err),
			"invalid password",
		)
	}
	if err != nil {
		return e.NewErrInternal(fmt.Errorf("comparing hash adn password: %w", err))
	}

	return nil
}

func (as *authService) checkExistAccessToken(ctx context.Context, token string) error {
	fmt.Println("accToken: ", token)

	if _, err := as.authRepo.AccessToken(ctx, token); err != nil {
		return e.NewErrUnauthorized(
			fmt.Errorf("checking exist access token: %w", err),
			"invalid token",
		)
	}

	return nil
}

func (as *authService) checkExistRefreshToken(ctx context.Context, token string) (core.RefreshToken, error) {
	rfToken, err := as.authRepo.RefreshToken(ctx, token)
	if err != nil {
		return core.RefreshToken{}, e.NewErrUnauthorized(
			fmt.Errorf("getting refresh token from db: %w", err),
			"invalid token",
		)
	}

	return rfToken, nil
}

func (as *authService) checkExpiredAccessToken(ctx context.Context, token string, tokenDetails jwttoken.JWTDetails) error {
	exp := time.Unix(int64(tokenDetails.EXP), 0)
	now := time.Now()

	if now.After(exp) {
		return as.deleteAccessTokenWithError(ctx, token)
	}

	return nil
}

func (as *authService) checkExpiredRefreshToken(ctx context.Context, token string, tokenDetails jwttoken.JWTDetails) error {
	exp := time.Unix(int64(tokenDetails.EXP), 0)
	now := time.Now()

	if now.After(exp) {
		return as.deleteRefreshTokenWithError(ctx, token)
	}

	return nil
}

func (as *authService) deleteRefreshTokenWithError(ctx context.Context, token string) error {
	if err := as.authRepo.DeleteRefreshToken(ctx, token); err != nil {
		return e.NewErrInternal(fmt.Errorf("deleting refresh token: %w", err))
	}

	return e.NewErrUnauthorized(
		errors.New("token expired"),
		"token expired",
	)
}

func (as *authService) deleteAccessTokenWithError(ctx context.Context, token string) error {
	if err := as.authRepo.DeleteAccessToken(ctx, token); err != nil {
		return e.NewErrInternal(fmt.Errorf("deleting access token: %w", err))
	}

	return e.NewErrUnauthorized(
		errors.New("token expired"),
		"token expired",
	)
}
