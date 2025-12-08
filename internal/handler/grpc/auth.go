package grpc_handler

import (
	"context"

	"github.com/GroVlAn/auth-example/api/auth"
	"github.com/GroVlAn/auth-example/internal/core"
)

func (h *GRPCHandler) Login(ctx context.Context, req *auth.AuthUser) (*auth.Tokens, error) {
	authUser := core.AuthUser{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	rfToken, accToken, err := h.AuthService.Authenticate(ctx, authUser)
	if err != nil {
		return nil, h.handleError(err)
	}

	tokens := &auth.Tokens{
		RefreshToken: &auth.RefreshToken{
			Token: rfToken.Token,
		},
		AccessToken: &auth.AccessToken{
			Token: accToken.Token,
		},
	}

	return tokens, nil
}

func (h *GRPCHandler) VerifyAccessToken(ctx context.Context, req *auth.AccessToken) (*auth.Success, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if _, err := h.AuthService.VerifyAccessToken(ctx, req.Token); err != nil {
		return nil, h.handleError(err)
	}

	return &auth.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) UpdateAccessToken(ctx context.Context, req *auth.RefreshToken) (*auth.AccessToken, error) {
	ctx = context.WithValue(ctx, core.RefreshTokenKey, req.Token)

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	newAccToken, err := h.AuthService.UpdateAccessToken(ctx)
	if err != nil {
		return nil, h.handleError(err)
	}

	return &auth.AccessToken{
		Token: newAccToken.Token,
	}, nil
}

func (h *GRPCHandler) Logout(ctx context.Context, req *auth.AccessToken) (*auth.Success, error) {
	ctx = context.WithValue(ctx, core.AccessTokenKey, req.Token)

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.AuthService.Logout(ctx); err != nil {
		return nil, h.handleError(err)
	}

	return &auth.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) LogoutAllDevices(ctx context.Context, req *auth.AccessToken) (*auth.Success, error) {
	ctx = context.WithValue(ctx, core.AccessTokenKey, req.Token)

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.AuthService.LogoutAllDevices(ctx); err != nil {
		return nil, h.handleError(err)
	}

	return &auth.Success{
		Success: true,
	}, nil
}
