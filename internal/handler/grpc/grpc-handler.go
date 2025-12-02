package grpc_handler

import (
	"context"
	"errors"
	"time"

	"github.com/GroVlAn/auth-example/api/auth"
	"github.com/GroVlAn/auth-example/api/role"
	"github.com/GroVlAn/auth-example/api/user"
	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, rfToken string) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) error
	Logout(ctx context.Context, refreshToken, accessToken string) error
	LogoutAllDevices(ctx context.Context, accessToken string) error
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

func (h *GRPCHandler) handleError(err error) error {
	var errValidation *e.ErrValidation
	var errWrapper *e.ErrWrapper

	if errors.As(err, &errValidation) {
		field, reason, ok := errValidation.FirstError()

		if ok {
			h.l.Error().Err(errWrapper.Unwrap()).Msgf("validation error occurred: field: %s, reason: %s", field, reason)

			return status.Errorf(codes.InvalidArgument, "field: %s, error: %s", field, reason)
		}
	}

	if errors.As(err, &errWrapper) {
		return h.handleErrorWrapper(errWrapper)
	}

	return status.Error(codes.Internal, "internal server error")
}

func (h *GRPCHandler) handleErrorWrapper(errWrapper *e.ErrWrapper) error {
	switch errWrapper.ErrorType() {
	case e.ErrorTypeNotFound:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error not found occurred")

		return status.Error(codes.NotFound, errWrapper.Error())
	case e.ErrorTypeConflict:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error conflict occurred")

		return status.Error(codes.AlreadyExists, errWrapper.Error())
	case e.ErrorTypeUnauthorized:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error unauthorized occurred")

		return status.Error(codes.Unauthenticated, errWrapper.Error())
	case e.ErrorTypeInternal:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error internal occurred")

		return status.Error(codes.Internal, errWrapper.Error())
	default:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error internal(not wrapped) occurred")

		return status.Error(codes.Internal, errWrapper.Error())
	}
}
