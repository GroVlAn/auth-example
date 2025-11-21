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

	rfToken, accToken, err := h.authService.Authenticate(ctx, authUser)
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

func (h *GRPCHandler) VerifyAccessToken(ctx context.Context, req *auth.Tokens) (*auth.Success, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.authService.VerifyAccessToken(ctx, req.AccessToken.Token); err != nil {
		return nil, h.handleError(err)
	}

	return &auth.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) UpdateAccessToken(ctx context.Context, req *auth.RefreshToken) (*auth.AccessToken, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	newAccToken, err := h.authService.UpdateAccessToken(ctx, req.Token)
	if err != nil {
		return nil, h.handleError(err)
	}

	return &auth.AccessToken{
		Token: newAccToken.Token,
	}, nil
}

func (h *GRPCHandler) Logout(ctx context.Context, req *auth.Tokens) (*auth.Success, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	err := h.authService.Logout(ctx, req.RefreshToken.Token, req.AccessToken.Token)
	if err != nil {
		return nil, h.handleError(err)
	}

	return &auth.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) LogoutAllDevices(ctx context.Context, req *auth.AccessToken) (*auth.Success, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	err := h.authService.LogoutAllDevices(ctx, req.Token)
	if err != nil {
		return nil, h.handleError(err)
	}

	return &auth.Success{
		Success: true,
	}, nil
}
