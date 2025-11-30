package grpc_handler

import (
	"context"

	"github.com/GroVlAn/auth-example/api/role"
	"github.com/GroVlAn/auth-example/internal/core"
)

func (h *GRPCHandler) CreateRole(ctx context.Context, req *role.Role) (*role.Success, error) {
	r := core.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.RoleService.CreateRole(ctx, r); err != nil {
		return nil, h.handleError(err)
	}

	return &role.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) CreatePermission(ctx context.Context, req *role.PermissionRequest) (*role.Success, error) {
	perm := core.Permission{
		Name:        req.Permission.Name,
		Description: req.Permission.Description,
	}

	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	if err := h.RoleService.CreatePermission(ctx, perm, req.RoleName); err != nil {
		return nil, h.handleError(err)
	}

	return &role.Success{
		Success: true,
	}, nil
}

func (h *GRPCHandler) GetPermissions(ctx context.Context, req *role.PermissionsRequest) (*role.Permissions, error) {
	ctx, cancel := context.WithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	perms, err := h.RoleService.Permissions(ctx, req.RoleName)
	if err != nil {
		return nil, h.handleError(err)
	}

	var res role.Permissions
	for _, p := range perms {
		res.Permissions = append(res.Permissions, &role.Permission{
			Name:        p.Name,
			Description: p.Description,
			IsDefault:   p.IsDefault,
		})
	}

	return &res, nil
}
