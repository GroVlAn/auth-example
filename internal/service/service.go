package service

import (
	"context"

	"github.com/GroVlAn/auth-example/internal/core"
)

type Authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser, userAgent string) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, rfToken string) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) error
}

type UserService interface {
	CreateUser(ctx context.Context, user core.User) error
	User(ctx context.Context, userReq core.UserRequest) (core.User, error)
}

type Service struct {
	auth Authenticator
	user UserService
}

func New(authRepo authRepo, userRepo userRepo, depsAuth DepsAuthService, depsUser DepsUserService) *Service {
	return &Service{
		auth: NewAuthService(authRepo, userRepo, depsAuth),
		user: NewUserService(userRepo, depsUser),
	}
}

func (s *Service) Auth() Authenticator {
	return s.auth
}

func (s *Service) User() UserService {
	return s.user
}
