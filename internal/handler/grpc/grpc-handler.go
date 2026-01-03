package grpc_handler

import (
	"context"
	"time"

	"github.com/GroVlAn/auth-example/api/auth"
	"github.com/GroVlAn/auth-example/api/role"
	"github.com/GroVlAn/auth-example/api/user"
	"github.com/GroVlAn/auth-example/internal/core"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
	"github.com/rs/zerolog"
)

type authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, refToken jwttoken.JWTDetails) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) (jwttoken.JWTDetails, error)
	VerifyRefreshToken(ctx context.Context, rfToken string) (jwttoken.JWTDetails, error)
	Logout(ctx context.Context, refToken, accToken jwttoken.JWTDetails) error
	LogoutAllDevices(ctx context.Context, accToken jwttoken.JWTDetails) error
}

type userService interface {
	CreateUser(ctx context.Context, user core.User) error
	User(ctx context.Context, userReq core.UserRequest) (core.User, error)
	SetRole(ctx context.Context, userID string, roleName string) error
	InactivateUser(ctx context.Context, userReq core.UserRequest) error
	RestoreUser(ctx context.Context, userReq core.UserRequest) error
	BanUser(ctx context.Context, userReq core.UserRequest) error
	UnbanUser(ctx context.Context, userReq core.UserRequest) error
}

type roleService interface {
	CreateRole(ctx context.Context, role core.Role) error
	CreatePermission(ctx context.Context, permission core.Permission, roleName string) error
	Permissions(ctx context.Context, roleName string) ([]core.Permission, error)
	VerifyPermission(ctx context.Context, accToken jwttoken.JWTDetails, permission string) (bool, error)
}
type Deps struct {
	DefaultTimeout time.Duration
}

type Services struct {
	UserService userService
	RoleService roleService
	AuthService authenticator
}

type GRPCHandler struct {
	user.UnimplementedUserServiceServer
	auth.UnimplementedAuthServiceServer
	role.UnimplementedRoleServiceServer
	l zerolog.Logger
	Services
	Deps
}

func New(l zerolog.Logger, services Services, deps Deps) *GRPCHandler {
	return &GRPCHandler{
		l:        l,
		Services: services,
		Deps:     deps,
	}
}
