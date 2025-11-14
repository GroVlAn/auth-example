package grpc_handler

import (
	"context"
	"errors"
	"time"

	"github.com/GroVlAn/auth-example/api/auth"
	"github.com/GroVlAn/auth-example/api/user"
	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser, userAgent string) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, rfToken string) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) error
}

type userService interface {
	CreateUser(ctx context.Context, user core.User) error
	User(ctx context.Context, userReq core.UserRequest) (core.User, error)
}

type Deps struct {
	DefaultTimeout time.Duration
}

type GRPCHandler struct {
	user.UnimplementedUserServiceServer
	auth.UnimplementedAuthServiceServer
	l           zerolog.Logger
	userService userService
	authService authenticator
	Deps
}

func New(l zerolog.Logger, userService userService, authService authenticator, deps Deps) *GRPCHandler {
	return &GRPCHandler{
		l:           l,
		userService: userService,
		authService: authService,
		Deps:        deps,
	}
}

func (h *GRPCHandler) handleError(err error) error {
	var errValidation *e.ErrValidation
	var errWrapper *e.ErrWrapper

	if errors.As(err, &errValidation) {
		field, reason, ok := errValidation.FirstError()

		if ok {
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
