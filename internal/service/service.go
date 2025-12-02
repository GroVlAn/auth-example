package service

import (
	"context"

	"github.com/GroVlAn/auth-example/internal/core"
)

type Authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, rfToken string) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) error
	Logout(ctx context.Context, refreshToken, accessToken string) error
	LogoutAllDevices(ctx context.Context, accessToken string) error
}

type UserService interface {
	CreateUser(ctx context.Context, user core.User) error
	User(ctx context.Context, userReq core.UserRequest) (core.User, error)
	SetRole(ctx context.Context, userID string, roleName string) error
	InactivateUser(ctx context.Context, userReq core.UserRequest) error
	RestoreUser(ctx context.Context, userReq core.UserRequest) error
	BanUser(ctx context.Context, userReq core.UserRequest) error
	UnbanUser(ctx context.Context, userReq core.UserRequest) error
	DeleteInactiveUser(ctx context.Context) error
}

type RoleService interface {
	CreateRole(ctx context.Context, role core.Role) error
	CreatePermission(ctx context.Context, permission core.Permission, roleName string) error
	Permissions(ctx context.Context, roleName string) ([]core.Permission, error)
}

type Service struct {
	auth Authenticator
	user UserService
	role RoleService
}

func New(authRepo authRepo, userRepo userRepo, roleRepo roleRepo, depsAuth DepsAuthService, depsUser DepsUserService) *Service {
	return &Service{
		auth: NewAuthService(authRepo, userRepo, depsAuth),
		user: NewUserService(userRepo, roleRepo, depsUser),
		role: NewRoleService(roleRepo),
	}
}

func (s *Service) Auth() Authenticator {
	return s.auth
}

func (s *Service) User() UserService {
	return s.user
}

func (s *Service) Role() RoleService {
	return s.role
}
