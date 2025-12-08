package service

import (
	"context"

	"github.com/GroVlAn/auth-example/internal/core"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
)

type Authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context) (core.AccessToken, error)
	VerifyRefreshToken(ctx context.Context, rfToken string) (jwttoken.JWTDetails, error)
	VerifyAccessToken(ctx context.Context, accToken string) (jwttoken.JWTDetails, error)
	Logout(ctx context.Context) error
	LogoutAllDevices(ctx context.Context) error
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
	VerifyPermission(ctx context.Context, permission string) (bool, error)
}

type Service struct {
	auth Authenticator
	user UserService
	role RoleService
}

type Repositories struct {
	AuthRepo authRepo
	UserRepo userRepo
	RoleRepo roleRepo
}

func New(
	r Repositories,
	secretKey string,
	depsAuth DepsAuthService,
	depsUser DepsUserService,
) *Service {
	return &Service{
		auth: NewAuthService(r.AuthRepo, r.UserRepo, secretKey, depsAuth),
		user: NewUserService(r.UserRepo, r.RoleRepo, depsUser),
		role: NewRoleService(r.RoleRepo, secretKey),
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
