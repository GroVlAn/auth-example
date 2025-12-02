package grpc_handler

import (
	"context"

	"github.com/GroVlAn/auth-example/api/user"
	"github.com/GroVlAn/auth-example/internal/core"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (h *GRPCHandler) CreateUser(ctx context.Context, req *user.User) (*user.Success, error) {
	u := core.User{
		ID:       req.ID,
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
		Fullname: req.Fullname,
	}

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.UserService.CreateUser(ctx, u); err != nil {
		return nil, h.handleError(err)
	}

	return &user.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) GetUser(ctx context.Context, req *user.UserRequest) (*user.User, error) {
	userReq := core.UserRequest{
		ID:       req.ID,
		Username: req.Username,
		Email:    req.Email,
	}

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	u, err := h.UserService.User(ctx, userReq)
	if err != nil {
		return nil, h.handleError(err)
	}

	return &user.User{
		ID:           u.ID,
		Username:     u.Username,
		Email:        u.Email,
		PasswordHash: u.Password,
		Fullname:     u.Fullname,
		CreatedAt:    timestamppb.New(u.CreatedAt),
	}, nil
}

func (h *GRPCHandler) SerRole(ctx context.Context, req *user.RoleRequest) (*user.Success, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.UserService.SetRole(ctx, req.UserId, req.RoleName); err != nil {
		return nil, h.handleError(err)
	}

	return &user.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) InactivateUser(ctx context.Context, req *user.UserRequest) (*user.Success, error) {
	return h.changeUserStatus(ctx, req, h.UserService.InactivateUser)
}

func (h *GRPCHandler) RestoreUser(ctx context.Context, req *user.UserRequest) (*user.Success, error) {
	return h.changeUserStatus(ctx, req, h.UserService.RestoreUser)
}

func (h *GRPCHandler) BanUser(ctx context.Context, req *user.UserRequest) (*user.Success, error) {
	return h.changeUserStatus(ctx, req, h.UserService.BanUser)
}

func (h *GRPCHandler) UnbanUser(ctx context.Context, req *user.UserRequest) (*user.Success, error) {
	return h.changeUserStatus(ctx, req, h.UserService.UnbanUser)
}

func (h *GRPCHandler) changeUserStatus(
	ctx context.Context,
	req *user.UserRequest,
	fn func(context.Context, core.UserRequest) error,
) (*user.Success, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	userReq := core.UserRequest{
		ID:       req.ID,
		Username: req.Username,
		Email:    req.Email,
	}

	if err := fn(ctx, userReq); err != nil {
		return nil, h.handleError(err)
	}

	return &user.Success{
		Success: true,
	}, nil
}
