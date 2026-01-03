package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
	"github.com/google/uuid"
)

type roleRepo interface {
	CreateRole(ctx context.Context, role core.Role) error
	RoleExist(ctx context.Context, roleName string) (bool, error)
	Role(ctx context.Context, roleName string) (core.Role, error)
	RoleByID(ctx context.Context, roleID string) (core.Role, error)
	CreatePermission(ctx context.Context, permission core.Permission, roleID, rpID string) error
	Permissions(ctx context.Context, roleID string) ([]core.Permission, error)
}

type roleCache interface {
	SetPermissions(roleID string, permissions map[string]struct{})
	GetPermissions(roleID string) (map[string]struct{}, bool)
	DeletePermissions(roleID string)
}

type RoleService struct {
	roleRepo roleRepo
	cache    roleCache
}

func NewRoleService(roleRepo roleRepo, cache roleCache) *RoleService {
	return &RoleService{
		roleRepo: roleRepo,
		cache:    cache,
	}
}

func (rs *RoleService) CreateRole(ctx context.Context, role core.Role) error {
	existedRole, err := rs.roleRepo.RoleExist(ctx, role.Name)
	if err != nil {
		return fmt.Errorf("getting existed role: %w", err)
	}
	if existedRole {
		return e.NewErrConflict(
			errors.New("role exist"),
			fmt.Sprintf("role: %s already exist", role.Name),
		)
	}

	role.ID = uuid.NewString()
	role.CreatedAt = time.Now()

	if err := rs.roleRepo.CreateRole(ctx, role); err != nil {
		return fmt.Errorf("creating new role: %w", err)
	}

	return nil
}

func (rs *RoleService) CreatePermission(ctx context.Context, permission core.Permission, roleName string) error {
	role, err := rs.roleRepo.Role(ctx, roleName)
	if err != nil {
		return fmt.Errorf("getting role by name: %w", err)
	}

	permission.ID = uuid.NewString()
	permission.CreatedAt = time.Now()
	rpID := uuid.NewString()

	if err := rs.roleRepo.CreatePermission(ctx, permission, role.ID, rpID); err != nil {
		return fmt.Errorf("creating permission: %w", err)
	}

	rs.cache.DeletePermissions(role.ID)

	return nil
}

func (rs *RoleService) Permissions(ctx context.Context, roleID string) ([]core.Permission, error) {
	permissions, err := rs.roleRepo.Permissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting permissions by role name: %w", err)
	}

	return permissions, nil
}

func (rs *RoleService) VerifyPermission(ctx context.Context, accToken jwttoken.JWTDetails, permission string) (bool, error) {
	if perm, ok := rs.cache.GetPermissions(accToken.RoleID); ok {
		_, exist := perm[permission]

		return exist, nil
	}

	permissions, err := rs.roleRepo.Permissions(ctx, accToken.RoleID)
	if err != nil {
		return false, fmt.Errorf("getting permissions by role name: %w", err)
	}

	permissionsMap := make(map[string]struct{}, len(permissions))

	for _, perm := range permissions {
		permissionsMap[perm.Name] = struct{}{}
	}

	rs.cache.SetPermissions(
		accToken.RoleID,
		permissionsMap,
	)

	_, exist := permissionsMap[permission]

	return exist, nil
}
