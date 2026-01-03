package grpc_handler

import (
	"context"
	"errors"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

func (h *GRPCHandler) sendInternalError(logMessage string) error {
	h.l.Error().Msg(logMessage)

	return status.Error(codes.Internal, "internal server error")
}

func (h *GRPCHandler) verifyPermission(ctx context.Context, permission string) error {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	accToken, ok := ctx.Value(core.AccessTokenKey).(jwttoken.JWTDetails)
	if !ok {
		return h.sendInternalError("context does not store access token")
	}

	ok, err := h.RoleService.VerifyPermission(ctx, accToken, permission)
	if err != nil {
		return h.handleError(err)
	}

	if !ok {
		return status.Error(codes.PermissionDenied, "access to method forbidden")
	}

	return nil
}
